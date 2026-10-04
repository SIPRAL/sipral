// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The DTLS 1.2 handshake of DTLS-SRTP, for either end, and the connection it
//! leaves behind (RFC 6347, RFC 5246, RFC 5763, RFC 5764).
//!
//! # Shape
//!
//! A [`Connection`] is one association with one peer. Nothing in it opens a
//! socket or reads a clock: the caller hands in every datagram that arrived
//! with [`Connection::handle_datagram`] and the passing of time with
//! [`Connection::handle_timeout`], sends what [`Connection::poll_transmit`]
//! gives it to the peer, wakes at [`Connection::poll_timeout`], and learns
//! what happened from [`Connection::poll_event`]: [`Event::Connected`] with
//! the SRTP keys, [`Event::Failed`] with the reason, [`Event::Closed`].
//!
//! Every random octet a handshake needs — the hello random, the ephemeral
//! ECDH key, the cookie secret — is drawn from the caller's [`Random`] when
//! the connection is made. A connection performs one handshake and no other,
//! so nothing is ever drawn later.
//!
//! # The handshake
//!
//! The one DTLS-SRTP needs. `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` over
//! P-256. The extended master secret in both hellos: RFC 7627 §5.2 lets
//! either end abort a handshake without it, and §5.4 forbids exporting keys
//! from a session without it, which is all DTLS-SRTP does with a session.
//! `use_srtp` in both hellos, with a profile both ends can key. And a
//! certificate from both ends: a server always asks for the client's and
//! refuses a client that sends none, and a client refuses a server that does
//! not ask, because RFC 5763 §5 has each end check the other's certificate
//! against the fingerprint the signalling carried. That fingerprint is the
//! only thing a certificate is checked against; when the signalling carried
//! several, RFC 8122 §5.1 picks the ones under the most preferred hash —
//! SHA-512, then SHA-384, SHA-256 and SHA-1 — and the certificate has to
//! match one of those.
//!
//! No renegotiation: RFC 8827 §6.5 has it refused with `no_renegotiation`,
//! and so it is. No session resumption. No MKI: a server answers a client's
//! MKI with an empty one, which RFC 5764 §4.1.3 reads as "cannot make use of
//! the MKI", and a client refuses a server that names one.
//!
//! # Flights and retransmission
//!
//! Messages go out in the flights of RFC 6347 §4.2.4, and the last flight sent
//! is kept whole, so that sending it again sends the same messages under the
//! same message sequence numbers, cut into records of their own. A flight
//! that expects an answer starts a timer at one second; each expiry sends it
//! again and doubles the wait, up to sixty seconds (§4.2.4.1); when
//! [`Retransmission::attempts`] retransmissions have gone unanswered the
//! handshake fails with [`Failure::Timeout`].
//!
//! A peer that sends its previous flight again has not received ours. It is
//! answered by sending ours again, and never by processing its flight a
//! second time: the reassembler hands each message out once, and a message
//! older than the flight being waited for is recognised as such without
//! being looked at. A retransmission of the flight being waited for, of which
//! part is already in, changes nothing — "partial reads ... do not cause
//! state transitions or timer resets". One answer per half of the initial
//! timer, so a flight that arrives duplicated, or spread over several
//! datagrams, is answered once and not once per datagram. The end that sends
//! the last flight, the server, goes on answering a retransmitted last flight
//! from the client for as long as the connection lives, but only once its
//! Finished, which travels protected, has authenticated: after the handshake
//! an epoch-0 fragment proves nothing about who sent it.
//!
//! # Epochs
//!
//! Finished is the only handshake message sent after ChangeCipherSpec, and so
//! the only one sent protected: a Finished fragment in epoch 0, or any other
//! handshake fragment in epoch 1, is discarded before the reassembler sees
//! it. A Finished can then only come from someone holding the keys.
//!
//! Once the peer's Finished is the only message left to come — a client that
//! has sent flight 5, a server that has verified CertificateVerify — every
//! epoch-0 handshake fragment numbered at or past it is discarded as well:
//! nothing the peer could still send there is unprotected, and anyone who can
//! spoof its address could otherwise end the handshake with a message out of
//! place, or have one take the Finished's number so that the genuine Finished
//! is read as a retransmission and the handshake waits until it times out.
//! A HelloRequest is discarded before reassembly at any point of a
//! handshake, for the second of those reasons (RFC 5246 §7.4.1.1 has a
//! client that is negotiating ignore it).
//!
//! ChangeCipherSpec itself changes nothing here. The read keys exist from the
//! moment the master secret does, and an epoch-1 record is opened with them
//! whether or not the ChangeCipherSpec announcing it has arrived — the two
//! travel in separate records and may be reordered — so nothing done to a
//! ChangeCipherSpec record moves a key. A few epoch-1 records that arrive
//! before the keys exist are held and opened once they do.
//!
//! # What is released, and when
//!
//! [`Event::Connected`], and the keys in it, come out only once the peer's
//! Finished has been verified against the transcript: for a client the
//! server's, which ends the handshake; for a server the client's, after
//! which it sends its own. Application data arriving before that is discarded
//! (§4.2.4 allows discarding or buffering), and none can be sent.
//!
//! # Alerts
//!
//! Invalid records — unreadable, unauthenticated, replayed — are discarded
//! without a word, as RFC 6347 §4.1.2.7 recommends where forging a datagram is
//! easy. A handshake that fails sends one fatal alert saying why
//! ([`Failure::alert`]), in the epoch this end is writing in, and ends; alerts
//! are not retransmitted (§4.2.7). A fatal alert from the peer, or a warning
//! RFC 5246 calls always fatal, ends the connection with
//! [`Failure::PeerAlert`]; `close_notify` is answered with a `close_notify` of
//! our own and ends it with [`Event::Closed`]; other warnings are ignored.
//!
//! An alert in epoch 0 is believed only while the handshake is running. Until
//! the keys exist a peer has no other way to say why it gave up, and anyone
//! able to forge that alert could as easily forge a handshake message that
//! ends the handshake anyway. Once the connection is established every
//! genuine alert arrives protected, and a plaintext one is discarded. And a
//! server that has accepted no ClientHello yet has had nothing from its peer
//! to refuse, so it discards one too: believed, a single forged datagram
//! would end it before its handshake began.
//!
//! # The server's cookie exchange
//!
//! With [`Config::cookie_exchange`] on, the default, a server answers a
//! ClientHello without a valid cookie with a HelloVerifyRequest and keeps
//! nothing (RFC 6347 §4.2.1): no allocation, no signature, no reassembly. So
//! until a cookie comes back a server reads only a ClientHello that arrives
//! in one fragment, and discards one that does not parse rather than answer
//! it — an answer would let a single forged datagram end the handshake. It
//! discards every alert and every protected record before that ClientHello
//! too, for the same reason and so as to hold nothing. A DTLS-SRTP
//! ClientHello is a couple of hundred octets and is not fragmented.
//!
//! The cookie is computed without a client address. A connection is one
//! association, and every datagram it produces goes where the caller sends
//! it, not to wherever a ClientHello claims to come from; a cookie that comes
//! back proves the client reads what is sent there, which is the property
//! the address in §4.2.1's formula exists to prove.

mod client;
mod flight;
mod server;

use core::fmt;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::alert::{Alert, AlertDescription};
use crate::exporter::SrtpKeys;
use crate::handshake::{
    self, Certificate as CertificateMessage, CipherSuite, Fragment, HandshakeType, Limits, Message,
    Offered, Reassembler, SrtpProtectionProfile, Transcript,
};
use crate::keys::{CertifiedKey, EcdsaKey};
use crate::prf::MasterSecret;
use crate::record::{self, ContentType, GcmProtection, ProtocolVersion, Record, ReplayWindow};
use crate::x509::{Certificate, Fingerprint, SubjectPublicKeyInfo};
use crate::{Error, Random, Role};

use client::Client;
use flight::{Expiry, Item, Timer, Writer};
use server::Server;

/// The largest UDP payload a connection writes unless told otherwise.
///
/// 1280, the smallest MTU IPv6 allows, less its 40-octet header and UDP's 8,
/// is 1232; 1200 leaves room below that for the extension headers and tunnel
/// overheads a path may add without saying so.
pub const DEFAULT_MAX_DATAGRAM: usize = 1200;

/// The cipher suite a server negotiates, its own key being P-256.
const SUITE: CipherSuite = CipherSuite::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
/// The suites a client offers, in that order: the one above, and the same
/// with the server's key exchange signed by RSA, for a server that certifies
/// with RSA. The record protection and the PRF are the same for both.
const CLIENT_SUITES: [CipherSuite; 2] = [SUITE, CipherSuite::ECDHE_RSA_WITH_AES_128_GCM_SHA256];

/// The SRTP profiles there are keys for, strongest first: this is the
/// server's own order of preference among whatever a client offers (RFC
/// 5764 §4.1.1 leaves the choice to the server), and the order a client
/// offers them in. The NULL profiles are refused outright: RFC 8827 §6.5
/// forbids negotiating encryption away.
const KEYABLE: [SrtpProtectionProfile; 4] = [
    SrtpProtectionProfile::AEAD_AES_256_GCM,
    SrtpProtectionProfile::AEAD_AES_128_GCM,
    SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
    SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
];

/// Epoch-1 records held while the keys to open them do not exist yet.
const EARLY_RECORDS: usize = 8;

/// The epoch a handshake message travels in: Finished after
/// ChangeCipherSpec, everything else before it.
fn epoch_of(msg_type: HandshakeType) -> u16 {
    u16::from(msg_type == HandshakeType::FINISHED)
}

/// How a flight is sent again (RFC 6347 §4.2.4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retransmission {
    /// The first wait for an answer: one second, "the minimum defined in RFC
    /// 6298", which §4.2.4.1 recommends over TCP's three for the latency of
    /// time-sensitive applications.
    pub initial: Duration,
    /// The cap on the doubled wait: sixty seconds, "the RFC 6298 maximum".
    pub max: Duration,
    /// How many times one flight is sent again before the handshake is given
    /// up. Six, which with the defaults above gives up two minutes after the
    /// flight first went out — 1 + 2 + 4 + 8 + 16 + 32 seconds of
    /// retransmissions and a last wait of sixty.
    pub attempts: u32,
}

impl Default for Retransmission {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(60),
            attempts: 6,
        }
    }
}

/// What one end of a handshake is.
#[derive(Debug, Clone)]
pub struct Config {
    /// Client or server: for DTLS-SRTP, what `a=setup` decided
    /// ([`crate::setup::dtls_role`]).
    pub role: Role,
    /// The key this end signs with.
    pub key: EcdsaKey,
    /// This end's certificate, for `key`. Its fingerprint is the one this
    /// end's signalling carries.
    pub certificate: Certificate,
    /// The fingerprints the peer's signalling carried, every `a=fingerprint`
    /// of its media description. At least one.
    pub peer_fingerprints: Vec<Fingerprint>,
    /// The SRTP profiles this end accepts, most preferred first: the list a
    /// client offers, and the order a server chooses in from what the client
    /// offered. Each at most once, and each one of the four there are keys
    /// for: `SRTP_AEAD_AES_256_GCM`, `SRTP_AEAD_AES_128_GCM` (RFC 7714
    /// §14.2), `SRTP_AES128_CM_HMAC_SHA1_80` and `_32` (RFC 5764 §4.1.2).
    pub srtp_profiles: Vec<SrtpProtectionProfile>,
    /// The largest UDP payload the path carries, the IP and UDP headers
    /// already taken off. Every datagram written fits it; a handshake message
    /// that does not is fragmented to.
    pub max_datagram: usize,
    /// For a server: whether a ClientHello is answered with a
    /// HelloVerifyRequest before any work is done for it. RFC 6347 §4.2.1
    /// makes that the default; a client ignores it.
    pub cookie_exchange: bool,
    /// The retransmission timer.
    pub retransmission: Retransmission,
    /// What reassembly holds for the peer.
    pub limits: Limits,
}

impl Config {
    /// A configuration with every setting but the four named at its default:
    /// every SRTP profile there are keys for, strongest first
    /// (`SRTP_AEAD_AES_256_GCM`, `SRTP_AEAD_AES_128_GCM`,
    /// `SRTP_AES128_CM_HMAC_SHA1_80`, `SRTP_AES128_CM_HMAC_SHA1_32`), datagrams of
    /// [`DEFAULT_MAX_DATAGRAM`], the cookie exchange on, the timers of RFC
    /// 6347 §4.2.4.1, reassembly's default limits.
    #[must_use]
    pub fn new(
        role: Role,
        key: EcdsaKey,
        certificate: Certificate,
        peer_fingerprints: Vec<Fingerprint>,
    ) -> Self {
        Self {
            role,
            key,
            certificate,
            peer_fingerprints,
            srtp_profiles: KEYABLE.to_vec(),
            max_datagram: DEFAULT_MAX_DATAGRAM,
            cookie_exchange: true,
            retransmission: Retransmission::default(),
            limits: Limits::default(),
        }
    }
}

/// Where a connection is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    /// The handshake is running, or a server is waiting for it to start.
    Handshaking,
    /// Both Finished messages are verified and the keys are out.
    Connected,
    /// The handshake or the connection failed; nothing more happens.
    Failed,
    /// One end sent `close_notify`; nothing more happens.
    Closed,
}

/// Why a handshake or a connection failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Failure {
    /// The peer's certificate matches none of the fingerprints its signalling
    /// carried. RFC 8122 §5.1: "the endpoint MUST NOT establish the TLS
    /// connection".
    FingerprintMismatch,
    /// The peer's certificate is not a DER certificate holding a P-256 key or
    /// an RSA key this crate accepts, or, from a server, not the kind of key
    /// the suite it chose is signed with (RFC 8422 §2.1, §2.2).
    UnusableCertificate,
    /// A certificate that DTLS-SRTP requires was not presented: the peer sent
    /// an empty Certificate or none at all, or as a server did not ask for
    /// this end's.
    NoCertificate,
    /// The peer's hello lacked the extended master secret.
    NoExtendedMasterSecret,
    /// The peer's hello lacked `use_srtp`, or named no profile this end
    /// accepts.
    NoSrtpProfile,
    /// No cipher suite, curve, signature algorithm or certificate type in
    /// common.
    NoCommonParameters,
    /// The peer does not speak DTLS 1.2.
    ProtocolVersion,
    /// A value outside what was offered or what the specification allows: a
    /// suite, profile, MKI, curve, point format or compression method that
    /// was not offered, or a public key that is not on the curve.
    IllegalParameter,
    /// A ServerHello carried an extension the ClientHello did not offer
    /// (RFC 5246 §7.4.1.4).
    UnsupportedExtension,
    /// An initial hello carried a non-empty `renegotiation_info` (RFC 5746
    /// §3.4, §3.6).
    Renegotiation,
    /// The peer's ServerKeyExchange or CertificateVerify signature did not
    /// verify.
    BadSignature,
    /// The peer's Finished does not match the transcript.
    BadFinished,
    /// A handshake message arrived that does not belong where it arrived.
    UnexpectedMessage,
    /// A handshake message could not be read.
    Malformed(Error),
    /// The peer sent a fatal alert, with this description.
    PeerAlert(AlertDescription),
    /// A flight went unanswered through every retransmission.
    Timeout,
    /// This end could not write what it had to send.
    Internal(Error),
}

impl Failure {
    /// The fatal alert this end sends when it fails for this reason, if it
    /// sends one: none for a failure the peer announced, or for a peer that
    /// is not answering.
    #[must_use]
    pub const fn alert(self) -> Option<AlertDescription> {
        Some(match self {
            Self::FingerprintMismatch => AlertDescription::BAD_CERTIFICATE,
            Self::UnusableCertificate => AlertDescription::UNSUPPORTED_CERTIFICATE,
            Self::NoCertificate
            | Self::NoExtendedMasterSecret
            | Self::NoSrtpProfile
            | Self::NoCommonParameters
            | Self::Renegotiation => AlertDescription::HANDSHAKE_FAILURE,
            Self::ProtocolVersion => AlertDescription::PROTOCOL_VERSION,
            Self::IllegalParameter => AlertDescription::ILLEGAL_PARAMETER,
            Self::UnsupportedExtension => AlertDescription::UNSUPPORTED_EXTENSION,
            Self::BadSignature | Self::BadFinished => AlertDescription::DECRYPT_ERROR,
            Self::UnexpectedMessage => AlertDescription::UNEXPECTED_MESSAGE,
            Self::Malformed(_) => AlertDescription::DECODE_ERROR,
            Self::Internal(_) => AlertDescription::INTERNAL_ERROR,
            Self::PeerAlert(_) | Self::Timeout => return None,
        })
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FingerprintMismatch => {
                f.write_str("the peer's certificate matches no fingerprint its signalling carried")
            }
            Self::UnusableCertificate => {
                f.write_str("the peer's certificate holds no key this end can verify with")
            }
            Self::NoCertificate => {
                f.write_str("a certificate DTLS-SRTP requires was not presented")
            }
            Self::NoExtendedMasterSecret => {
                f.write_str("the peer does not use the extended master secret")
            }
            Self::NoSrtpProfile => f.write_str("no SRTP protection profile in common"),
            Self::NoCommonParameters => {
                f.write_str("no cipher suite, curve or signature algorithm in common")
            }
            Self::ProtocolVersion => f.write_str("the peer does not speak DTLS 1.2"),
            Self::IllegalParameter => f.write_str("the peer chose a value that was not offered"),
            Self::UnsupportedExtension => {
                f.write_str("the peer sent an extension that was not offered")
            }
            Self::Renegotiation => f.write_str("the peer asked to renegotiate"),
            Self::BadSignature => f.write_str("a signature from the peer did not verify"),
            Self::BadFinished => f.write_str("the peer's Finished does not match the transcript"),
            Self::UnexpectedMessage => f.write_str("a handshake message arrived out of place"),
            Self::Malformed(error) => write!(f, "a handshake message could not be read: {error}"),
            Self::PeerAlert(description) => {
                write!(f, "the peer sent a fatal alert ({})", description.0)
            }
            Self::Timeout => f.write_str("the peer did not answer"),
            Self::Internal(error) => write!(f, "the handshake could not be written: {error}"),
        }
    }
}

/// Something that happened.
#[derive(Debug)]
pub enum Event {
    /// The handshake completed, and these are the SRTP keys it exported.
    Connected(SrtpKeying),
    /// Application data from the peer, only ever after [`Event::Connected`].
    /// DTLS-SRTP sends none — RFC 5764 §4.1 carries media in SRTP, outside
    /// DTLS — but a peer may.
    ApplicationData(Vec<u8>),
    /// The handshake or the connection failed.
    Failed(Failure),
    /// The peer sent `close_notify`, which was answered.
    Closed,
}

/// The SRTP keys a completed handshake exported (RFC 5764 §4.2), arranged for
/// this end.
///
/// A key and a salt per direction, of the width the negotiated profile's own
/// SRTP crypto suite calls for -- sixteen or thirty-two octets of key,
/// fourteen or twelve of salt: in `sipral-rtp`, `srtp::Master::new(key,
/// salt)` for each direction, and a policy whose suite is the profile's —
/// `SRTP_AES128_CM_HMAC_SHA1_80` is `AES_CM_128_HMAC_SHA1_80`, `_32` is
/// `_32`, and `SRTP_AEAD_AES_128_GCM`/`_256_GCM` are `AEAD_AES_128_GCM`/
/// `AEAD_AES_256_GCM`. No MKI is ever agreed, so none is carried. The key
/// derivation rate is zero, as RFC 5764 §4.1.2 fixes it.
///
/// Wiped when dropped, and never printed.
pub struct SrtpKeying {
    role: Role,
    keys: SrtpKeys,
}

impl SrtpKeying {
    /// The role this end played.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The profile agreed.
    #[must_use]
    pub const fn profile(&self) -> SrtpProtectionProfile {
        self.keys.profile()
    }

    /// The master key protecting what this end sends.
    #[must_use]
    pub fn local_master_key(&self) -> &[u8] {
        self.keys.master_key(self.role)
    }

    /// The master salt protecting what this end sends.
    #[must_use]
    pub fn local_master_salt(&self) -> &[u8] {
        self.keys.master_salt(self.role)
    }

    /// The master key protecting what the peer sends.
    #[must_use]
    pub fn remote_master_key(&self) -> &[u8] {
        self.keys.master_key(self.role.peer())
    }

    /// The master salt protecting what the peer sends.
    #[must_use]
    pub fn remote_master_salt(&self) -> &[u8] {
        self.keys.master_salt(self.role.peer())
    }
}

impl fmt::Debug for SrtpKeying {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtpKeying")
            .field("role", &self.role)
            .field("profile", &self.keys.profile())
            .finish_non_exhaustive()
    }
}

/// A configuration, checked and kept.
struct Settings {
    role: Role,
    key: EcdsaKey,
    certificate: Vec<u8>,
    peer_fingerprints: Vec<Fingerprint>,
    srtp_profiles: Vec<SrtpProtectionProfile>,
    max_datagram: usize,
    cookie_exchange: bool,
    retransmission: Retransmission,
    limits: Limits,
}

impl Settings {
    fn from_config(config: Config) -> Result<Self, Error> {
        if config.peer_fingerprints.is_empty()
            || config.srtp_profiles.is_empty()
            || config
                .srtp_profiles
                .iter()
                .any(|profile| !KEYABLE.contains(profile))
            // a preference order names each profile once; RFC 5764 §4.1.1's
            // list is the client's "in descending order of preference", which
            // a repeated entry makes two orders at once
            || config
                .srtp_profiles
                .iter()
                .enumerate()
                .any(|(at, profile)| config.srtp_profiles.iter().take(at).any(|p| p == profile))
            || config.retransmission.initial.is_zero()
            || config.retransmission.max < config.retransmission.initial
        {
            return Err(Error::IllegalValue);
        }
        handshake::record_payload_budget(config.max_datagram, record::GCM_OVERHEAD)?;
        let certified =
            SubjectPublicKeyInfo::from_certificate(config.certificate.der())?.p256_key()?;
        if certified != config.key.peer_key() {
            return Err(Error::IllegalValue);
        }
        Ok(Self {
            role: config.role,
            certificate: config.certificate.der().to_vec(),
            key: config.key,
            peer_fingerprints: config.peer_fingerprints,
            srtp_profiles: config.srtp_profiles,
            max_datagram: config.max_datagram,
            cookie_exchange: config.cookie_exchange,
            retransmission: config.retransmission,
            limits: config.limits,
        })
    }

    /// RFC 8122 §5.1: "select the set of fingerprints that use its most
    /// preferred hash function (out of those offered by the peer) and verify
    /// that each certificate used matches one fingerprint out of that set".
    fn fingerprint_matches(&self, certificate: &[u8]) -> bool {
        let Some(preferred) = self
            .peer_fingerprints
            .iter()
            .map(Fingerprint::hash)
            .max_by_key(|hash| hash.preference())
        else {
            return false;
        };
        self.peer_fingerprints
            .iter()
            .filter(|fingerprint| fingerprint.hash() == preferred)
            .fold(false, |matched, fingerprint| {
                fingerprint.matches(certificate) | matched
            })
    }
}

/// Everything a connection holds that both roles use.
struct Core {
    settings: Settings,
    status: State,
    transcript: Transcript,
    reassembler: Reassembler,
    /// The `message_seq` of the next message this end sends.
    send_seq: u16,
    writer: Writer,
    read1: Option<(ReplayWindow, GcmProtection)>,
    /// The last flight sent, while it may have to be sent again.
    flight: Option<Vec<Item>>,
    /// The peer's `next_receive_seq` when that flight went out: a message
    /// numbered below it belongs to a flight the peer sent before ours.
    flight_start: u32,
    timer: Timer,
    last_sent: Option<Instant>,
    early: Vec<Vec<u8>>,
    events: VecDeque<Event>,
}

impl Core {
    fn new(settings: Settings) -> Self {
        Self {
            status: State::Handshaking,
            transcript: Transcript::new(),
            reassembler: Reassembler::new(settings.limits),
            send_seq: 0,
            writer: Writer::new(settings.max_datagram),
            read1: None,
            flight: None,
            flight_start: 0,
            timer: Timer::new(settings.retransmission),
            last_sent: None,
            early: Vec::new(),
            events: VecDeque::new(),
            settings,
        }
    }

    const fn is_open(&self) -> bool {
        matches!(self.status, State::Handshaking | State::Connected)
    }

    /// A message this end sends: numbered, added to the transcript, ready to
    /// go into a flight.
    fn message(&mut self, msg_type: HandshakeType, body: Vec<u8>) -> Result<Item, Failure> {
        let message_seq = self.send_seq;
        self.send_seq = message_seq
            .checked_add(1)
            .ok_or(Failure::Internal(Error::SequenceExhausted))?;
        self.transcript
            .add(msg_type, message_seq, &body)
            .map_err(Failure::Internal)?;
        Ok(Item::Handshake {
            msg_type,
            message_seq,
            body,
        })
    }

    /// Add a message the peer sent to the transcript.
    fn transcribe(&mut self, message: &Message) -> Result<(), Failure> {
        self.transcript
            .add(message.msg_type, message.message_seq, &message.body)
            .map_err(Failure::Internal)
    }

    fn send_flight(
        &mut self,
        items: Vec<Item>,
        expects_reply: bool,
        now: Instant,
    ) -> Result<(), Failure> {
        self.flight = Some(items);
        self.flight_start = self.reassembler.next_message_seq();
        self.timer.start(now, expects_reply);
        self.transmit_flight(now)
    }

    fn transmit_flight(&mut self, now: Instant) -> Result<(), Failure> {
        if let Some(items) = &self.flight {
            self.writer.flight(items).map_err(Failure::Internal)?;
            self.last_sent = Some(now);
        }
        Ok(())
    }

    /// The peer sent a flight from before our last one again: send ours
    /// again, at most once per half of the initial timer.
    ///
    /// The give-up timer is left running on its own schedule. This prompt
    /// travels in epoch 0, before any key exists, so nothing ties it to the
    /// peer that owns the handshake — anyone able to spoof that address can
    /// forge it, as often as the quiet gap above lets one through. Letting
    /// it push the deadline back would let a forged stream of these hold a
    /// handshake open forever, long past the point the real peer, if it is
    /// even still there, would have been given up on. RFC 6347 §4.2.4 asks
    /// only that the flight be sent again, not that the deadline move.
    fn on_peer_retransmission(&mut self, now: Instant) {
        let gap = self.settings.retransmission.initial / 2;
        if self
            .last_sent
            .and_then(|sent| sent.checked_add(gap))
            .is_some_and(|quiet_until| now < quiet_until)
        {
            return;
        }
        if let Err(failure) = self.transmit_flight(now) {
            self.fail(failure);
        }
    }

    /// The record keys of epoch 1, both directions, from the master secret.
    fn install_keys(&mut self, master: &MasterSecret) -> Result<(), Failure> {
        let role = self.settings.role;
        let block = master.key_block();
        let epoch1 = self.writer.epoch0.advance().map_err(Failure::Internal)?;
        self.writer.epoch1 = Some((epoch1, block.protection(role)));
        self.read1 = Some((ReplayWindow::new(), block.protection(role.peer())));
        Ok(())
    }

    /// The peer's key, from the first certificate of its Certificate message,
    /// once that certificate is the one its signalling named.
    ///
    /// P-256 or RSA: the key is only ever checked against, so its kind is
    /// the peer's business, and a peer that certifies with RSA — FreeSWITCH
    /// as it ships — is refused by nothing else.
    fn peer_key(&self, message: &CertificateMessage) -> Result<CertifiedKey, Failure> {
        let certificate = message
            .certificate_list
            .first()
            .ok_or(Failure::NoCertificate)?;
        if !self.settings.fingerprint_matches(certificate) {
            return Err(Failure::FingerprintMismatch);
        }
        SubjectPublicKeyInfo::from_certificate(certificate)
            .and_then(|info| info.certified_key())
            .map_err(|_| Failure::UnusableCertificate)
    }

    /// Both Finished messages are verified: export the keys.
    fn complete(
        &mut self,
        master: &MasterSecret,
        profile: SrtpProtectionProfile,
    ) -> Result<(), Failure> {
        let keys = master.srtp_keys(profile).map_err(Failure::Internal)?;
        self.status = State::Connected;
        self.timer.stop();
        self.early.clear();
        self.events.push_back(Event::Connected(SrtpKeying {
            role: self.settings.role,
            keys,
        }));
        Ok(())
    }

    fn hold_early(&mut self, record: &Record<'_>) {
        if self.status != State::Handshaking || self.early.len() >= EARLY_RECORDS {
            return;
        }
        let mut held = Vec::with_capacity(record::HEADER_LEN + record.fragment.len());
        if record.header.encode(&mut held).is_ok() {
            held.extend_from_slice(record.fragment);
            self.early.push(held);
        }
    }

    fn on_alert(&mut self, alert: Alert) {
        if alert.description == AlertDescription::CLOSE_NOTIFY {
            // RFC 5246 §7.2.1: "The other party MUST respond with a
            // close_notify alert of its own and close down the connection
            // immediately"
            self.send_alert(Alert::warning(AlertDescription::CLOSE_NOTIFY));
            self.end(State::Closed);
            self.events.push_back(Event::Closed);
        } else if alert.is_fatal() {
            self.end(State::Failed);
            self.events
                .push_back(Event::Failed(Failure::PeerAlert(alert.description)));
        }
    }

    /// Send an alert, best effort: one that cannot be written — the epoch's
    /// sequence numbers spent — has nowhere else to go.
    fn send_alert(&mut self, alert: Alert) {
        let _unsent = self.writer.alert(alert);
    }

    fn fail(&mut self, failure: Failure) {
        if !self.is_open() {
            return;
        }
        if let Some(description) = failure.alert() {
            self.send_alert(Alert::fatal(description));
        }
        self.end(State::Failed);
        self.events.push_back(Event::Failed(failure));
    }

    fn end(&mut self, status: State) {
        self.status = status;
        self.timer.stop();
        self.flight = None;
        self.early.clear();
    }
}

enum Handshake {
    Client(Client),
    Server(Server),
}

/// One end of a DTLS-SRTP association.
pub struct Connection {
    core: Core,
    handshake: Handshake,
}

impl Connection {
    /// One end of a handshake.
    ///
    /// A client's ClientHello is waiting in [`Connection::poll_transmit`] when
    /// this returns, with the retransmission timer running from `now`. A
    /// server waits for one.
    ///
    /// # Errors
    ///
    /// - [`Error::IllegalValue`] for a configuration no DTLS-SRTP handshake
    ///   can come of: no fingerprint for the peer, no SRTP profile, one
    ///   there are no keys for or one named twice, a certificate that is not for `key`, a timer
    ///   that starts at zero or is capped below its start;
    /// - [`Error::MtuTooSmall`] for a datagram that cannot carry one octet of
    ///   protected handshake data;
    /// - what reading the certificate reports, and [`Error::RandomRejected`]
    ///   when `random` keeps producing octets no key can be made from.
    pub fn new<R: Random + ?Sized>(
        config: Config,
        random: &mut R,
        now: Instant,
    ) -> Result<Self, Error> {
        let settings = Settings::from_config(config)?;
        let handshake = match settings.role {
            Role::Client => Handshake::Client(Client::new(random, &settings.srtp_profiles)?),
            Role::Server => Handshake::Server(Server::new(random)?),
        };
        let mut connection = Self {
            core: Core::new(settings),
            handshake,
        };
        if let Handshake::Client(client) = &mut connection.handshake {
            client
                .start(&mut connection.core, now)
                .map_err(|failure| match failure {
                    Failure::Internal(error) | Failure::Malformed(error) => error,
                    _ => Error::IllegalValue,
                })?;
        }
        Ok(connection)
    }

    /// The role this end plays.
    #[must_use]
    pub const fn role(&self) -> Role {
        self.core.settings.role
    }

    /// Where the connection is.
    #[must_use]
    pub const fn state(&self) -> State {
        self.core.status
    }

    /// Take a datagram that arrived from the peer.
    ///
    /// Every record in it is read in turn; a record that cannot be read ends
    /// the datagram, since its length is what says where the next begins.
    pub fn handle_datagram(&mut self, datagram: &[u8], now: Instant) {
        for record in record::records(datagram) {
            if !self.core.is_open() {
                return;
            }
            let Ok(record) = record else {
                return;
            };
            match record.header.epoch {
                0 => self.on_plaintext(&record, now),
                1 => self.on_protected(&record, now),
                _ => {}
            }
        }
        self.open_early(now);
    }

    /// Take the passing of time. Harmless to call early or often.
    pub fn handle_timeout(&mut self, now: Instant) {
        if self.core.status != State::Handshaking {
            return;
        }
        match self.core.timer.expire(now) {
            Expiry::NotYet => {}
            Expiry::GiveUp => self.core.fail(Failure::Timeout),
            Expiry::Retransmit => {
                if let Err(failure) = self.core.transmit_flight(now) {
                    self.core.fail(failure);
                }
            }
        }
    }

    /// When [`Connection::handle_timeout`] next has something to do.
    #[must_use]
    pub const fn poll_timeout(&self) -> Option<Instant> {
        match self.core.status {
            State::Handshaking => self.core.timer.deadline(),
            State::Connected | State::Failed | State::Closed => None,
        }
    }

    /// The next datagram to send to the peer.
    pub fn poll_transmit(&mut self) -> Option<Vec<u8>> {
        self.core.writer.outbox.pop_front()
    }

    /// The next event.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.core.events.pop_front()
    }

    /// Send application data, protected, in a datagram of its own.
    ///
    /// # Errors
    ///
    /// [`Error::NotConnected`] before [`Event::Connected`] and after the
    /// connection failed or closed; [`Error::TooLarge`] for more than 2^14
    /// octets; [`Error::SequenceExhausted`] once the epoch's sequence numbers
    /// are spent.
    pub fn send_application_data(&mut self, data: &[u8]) -> Result<(), Error> {
        if self.core.status != State::Connected {
            return Err(Error::NotConnected);
        }
        self.core.writer.application_data(data)
    }

    /// Close: send `close_notify` and stop. Nothing is sent or received after.
    pub fn close(&mut self) {
        if !self.core.is_open() {
            return;
        }
        self.core
            .send_alert(Alert::warning(AlertDescription::CLOSE_NOTIFY));
        self.core.end(State::Closed);
    }

    fn on_plaintext(&mut self, record: &Record<'_>, now: Instant) {
        let version = record.header.version;
        if version != ProtocolVersion::DTLS_1_2 && version != ProtocolVersion::DTLS_1_0 {
            return;
        }
        let Ok(payload) = record.plaintext() else {
            return;
        };
        match record.header.content_type {
            ContentType::HANDSHAKE => self.on_handshake(0, record.header.sequence, payload, now),
            ContentType::ALERT
                if self.core.status == State::Handshaking && !self.is_listening() =>
            {
                if let Ok(alert) = Alert::parse(payload) {
                    self.core.on_alert(alert);
                }
            }
            _ => {}
        }
    }

    /// Whether the one message left for the peer to send is its Finished: a
    /// client that has sent flight 5, a server that has verified the
    /// client's CertificateVerify.
    fn awaits_finished(&self) -> bool {
        match &self.handshake {
            Handshake::Client(client) => client.awaits_finished(),
            Handshake::Server(server) => server.awaits_finished(),
        }
    }

    /// Whether this is a server that has accepted no ClientHello yet, and so
    /// reads nothing but one.
    fn is_listening(&self) -> bool {
        matches!(&self.handshake, Handshake::Server(server) if server.is_listening())
    }

    fn on_protected(&mut self, record: &Record<'_>, now: Instant) {
        if record.header.version != ProtocolVersion::DTLS_1_2 {
            return;
        }
        if self.core.read1.is_none() {
            if !self.is_listening() {
                self.core.hold_early(record);
            }
            return;
        }
        let mut plaintext = Vec::new();
        if let Some((window, protection)) = self.core.read1.as_mut() {
            // RFC 6347 §4.1.2.6: the window first, and moved only once the
            // record has authenticated
            if window.check(record.header.sequence).is_err()
                || protection.open(record, &mut plaintext).is_err()
            {
                return;
            }
            window.accept(record.header.sequence);
        }
        match record.header.content_type {
            ContentType::HANDSHAKE => {
                self.on_handshake(1, record.header.sequence, &plaintext, now);
            }
            ContentType::ALERT => {
                if let Ok(alert) = Alert::parse(&plaintext) {
                    self.core.on_alert(alert);
                }
            }
            ContentType::APPLICATION_DATA if self.core.status == State::Connected => {
                self.core
                    .events
                    .push_back(Event::ApplicationData(plaintext));
            }
            _ => {}
        }
    }

    fn open_early(&mut self, now: Instant) {
        if self.core.read1.is_none() || self.core.early.is_empty() {
            return;
        }
        for held in std::mem::take(&mut self.core.early) {
            if !self.core.is_open() {
                return;
            }
            if let Ok((record, _)) = Record::parse(&held) {
                self.on_protected(&record, now);
            }
        }
    }

    fn on_handshake(&mut self, epoch: u16, record_sequence: u64, payload: &[u8], now: Instant) {
        for fragment in handshake::fragments(payload) {
            if !self.core.is_open() {
                return;
            }
            let Ok(fragment) = fragment else {
                return;
            };
            self.on_fragment(epoch, record_sequence, &fragment, now);
        }
    }

    fn on_fragment(
        &mut self,
        epoch: u16,
        record_sequence: u64,
        fragment: &Fragment<'_>,
        now: Instant,
    ) {
        if let Handshake::Server(server) = &mut self.handshake
            && server.is_listening()
        {
            if epoch == 0
                && let Err(failure) = server.listen(&mut self.core, record_sequence, fragment, now)
            {
                self.core.fail(failure);
            }
            return;
        }
        let header = fragment.header;
        let seq = u32::from(header.message_seq);
        if self.core.status == State::Connected {
            // a protected HelloRequest or ClientHello belongs to no flight of
            // the handshake that is over, whatever its number: RFC 6347
            // §4.2.2 numbers a new handshake from 0 again
            let asks_to_renegotiate = epoch == 1
                && matches!(
                    header.msg_type,
                    HandshakeType::HELLO_REQUEST | HandshakeType::CLIENT_HELLO
                );
            if asks_to_renegotiate {
                // RFC 8827 §6.5: "MUST reject it with a "no_renegotiation"
                // alert"; the connection carries on
                self.core
                    .send_alert(Alert::warning(AlertDescription::NO_RENEGOTIATION));
            } else if epoch == 1 && seq < self.core.flight_start {
                // only the client's Finished, which authenticated, says its
                // last flight is being sent again: an epoch-0 fragment
                // anyone can forge, and answered it would have this end send
                // its flight to whoever spoofs the peer for as long as the
                // connection lives
                self.core.on_peer_retransmission(now);
            }
            return;
        }
        if epoch != epoch_of(header.msg_type) {
            return;
        }
        // RFC 5246 §7.4.1.1: a client that is negotiating ignores a
        // HelloRequest, and a server never takes one. Dropped before
        // reassembly, so that it never takes the `message_seq` of the genuine
        // message that is due under it
        if header.msg_type == HandshakeType::HELLO_REQUEST {
            return;
        }
        // RFC 6347 §4.1.2.7: once all that is left is the peer's Finished,
        // which travels protected, nothing in epoch 0 can be the next message;
        // one at or past it is forged and would otherwise end the handshake
        // or take the Finished's place. What comes before it is still read,
        // as the retransmission it is
        if epoch == 0 && seq >= self.core.reassembler.next_message_seq() && self.awaits_finished() {
            return;
        }
        match self.core.reassembler.offer(fragment) {
            Ok(Offered::Retransmission) if seq < self.core.flight_start => {
                self.core.on_peer_retransmission(now);
            }
            Ok(Offered::Accepted | Offered::Replaced) => self.deliver(now),
            Ok(Offered::Retransmission | Offered::TooFarAhead) | Err(_) => {}
        }
    }

    /// Hand every complete message, in sequence, to the role.
    fn deliver(&mut self, now: Instant) {
        while self.core.status == State::Handshaking {
            let Some(message) = self.core.reassembler.next_message() else {
                return;
            };
            let outcome = match &mut self.handshake {
                Handshake::Client(client) => client.on_message(&mut self.core, &message, now),
                Handshake::Server(server) => server.on_message(&mut self.core, &message, now),
            };
            if let Err(failure) = outcome {
                self.core.fail(failure);
            }
        }
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("role", &self.core.settings.role)
            .field("state", &self.core.status)
            .finish_non_exhaustive()
    }
}

// last, so that `scripts/check.sh`'s clock scan, which stops reading a file
// at its first test attribute, reads all of this one
#[cfg(test)]
mod tests;
