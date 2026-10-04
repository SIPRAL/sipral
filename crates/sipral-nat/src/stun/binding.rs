// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Asking a server where we appear from (RFC 8489 §6.2.1 and §9.2).
//!
//! No socket, no clock and no random number generator. The caller supplies the
//! transaction id and the time, gets back the datagram to send and the moment
//! the next thing has to happen, and feeds in what arrives. Everything the
//! retransmission schedule and the credential exchange do is therefore
//! reproducible in a test without a network and without waiting.
//!
//! One transaction at a time, on purpose. A binding request is idempotent and
//! its answer is a single address; a caller that wants several servers runs
//! several of these.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::attribute::{AttributeType, PasswordAlgorithm, error_code};
use super::builder::{BuildError, MessageBuilder};
use super::message::{Class, Integrity, Message, Method, TransactionId};
use crate::crypto::Digest;
use crate::crypto::md5::Md5;
use crate::crypto::sha256::Sha256;

/// "The initial value for RTO SHOULD be greater than or equal to 500 ms [...]
/// In fixed-line access links, a value of 500 ms is RECOMMENDED" (§6.2.1).
pub const DEFAULT_RTO: Duration = Duration::from_millis(500);

/// Requests sent before the transaction gives up (§6.2.1).
pub const DEFAULT_RC: u32 = 7;

/// Multiples of the initial RTO to wait after the last request (§6.2.1).
pub const DEFAULT_RM: u32 = 16;

/// A ceiling on any single wait, so that a caller who configures an absurd Rc
/// gets a transaction that ends rather than one that never fires again.
const MAX_INTERVAL: Duration = Duration::from_secs(600);

/// How many times a challenge may be answered before the exchange is called a
/// loop. One 401 and a couple of stale nonces are a normal life; more than
/// that is a server that will never be satisfied.
const MAX_CHALLENGES: u32 = 3;

/// The thirteen characters a server prepends to the nonce to say it implements
/// RFC 8489 (§9.2).
pub(crate) const NONCE_COOKIE: &[u8] = b"obMatJos2";

/// Bit 0 of the security features: the server is offering a choice of password
/// algorithm (§18.1).
pub(crate) const FEATURE_PASSWORD_ALGORITHMS: u8 = 0x80;

/// A password, and the promise not to print it.
///
/// The bytes are overwritten on drop. That is best effort and said plainly:
/// only a volatile write is guaranteed to survive an optimiser, and a volatile
/// write needs `unsafe`, which this crate denies.
#[derive(Clone)]
pub struct Password(Box<[u8]>);

impl Password {
    /// Take a password.
    #[must_use]
    pub fn new(password: &str) -> Self {
        Self(Box::from(password.as_bytes()))
    }

    pub(crate) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            *byte = 0;
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// The long-term credential a STUN or TURN server was provisioned with.
///
/// The realm is not here: the server names it in the challenge, and a client
/// that decided the realm itself would be answering a question nobody asked.
#[derive(Clone)]
pub struct LongTermCredentials {
    username: String,
    password: Password,
}

impl LongTermCredentials {
    /// Take a user name and password.
    #[must_use]
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_owned(),
            password: Password::new(password),
        }
    }

    /// The user name, which goes in the message and is not a secret.
    #[must_use]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// The password, for the one thing that may see it: key derivation.
    pub(crate) fn password(&self) -> &[u8] {
        self.password.expose()
    }
}

impl fmt::Debug for LongTermCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LongTermCredentials")
            .field("username", &self.username)
            .finish_non_exhaustive()
    }
}

/// How the client behaves.
pub struct BindingConfig {
    /// The first retransmission interval, doubling from there.
    pub rto: Duration,
    /// Requests to send before giving up.
    pub rc: u32,
    /// Multiples of `rto` to wait after the last request.
    pub rm: u32,
    /// What to put in SOFTWARE, if anything.
    ///
    /// The default is nothing. The specification says a request SHOULD carry
    /// it and then says, in §16.1.2, that announcing the exact version of what
    /// you are running tells an attacker which bugs to try.
    pub software: Option<String>,
    /// Whether to add FINGERPRINT. On by default, because the socket this runs
    /// on is the media socket and the fingerprint is what makes the difference
    /// between STUN and RTP unambiguous.
    pub fingerprint: bool,
    /// The credential to answer a challenge with, if the server issues one.
    pub credentials: Option<LongTermCredentials>,
}

impl Default for BindingConfig {
    fn default() -> Self {
        Self {
            rto: DEFAULT_RTO,
            rc: DEFAULT_RC,
            rm: DEFAULT_RM,
            software: None,
            fingerprint: true,
            credentials: None,
        }
    }
}

impl fmt::Debug for BindingConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingConfig")
            .field("rto", &self.rto)
            .field("rc", &self.rc)
            .field("rm", &self.rm)
            .field("software", &self.software)
            .field("fingerprint", &self.fingerprint)
            .field("authenticated", &self.credentials.is_some())
            .finish()
    }
}

/// What the client wants next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Nothing to do. A datagram that was not this transaction's business
    /// lands here, and so does a deadline that has not arrived.
    Idle,
    /// Send `BindingClient::datagram` to the server.
    Transmit,
    /// The server wants credentials. Draw a fresh transaction id and call
    /// `BindingClient::retry`.
    Challenged,
    /// The transaction succeeded and this is where we appear from.
    Mapped(SocketAddr),
    /// The transaction is over and did not answer the question.
    Failed(Failure),
}

/// Why a transaction ended without an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Rc requests went out and Rm times the RTO passed after the last one.
    TimedOut,
    /// Responses arrived and every one of them failed its integrity check, so
    /// the timeout is reported as what it was rather than as silence (§9.2.5).
    IntegrityViolated,
    /// The server refused the credentials, or asked for credentials that were
    /// never configured.
    Unauthenticated,
    /// The response carried a comprehension-required attribute this
    /// implementation does not understand (§6.3.3), or the server answered 420.
    UnknownAttribute,
    /// 300 (Try Alternate): the same request belongs at this address instead
    /// (§10). Whether to follow it is the caller's decision, and following it
    /// blindly in a loop is what the RFC warns about.
    Alternate(SocketAddr),
    /// An error response this client does not act on.
    Rejected {
        /// The code the server sent.
        code: u16,
    },
    /// A success response with no address in it, which is the one thing a
    /// binding response exists to carry (§6.3.3).
    NoReflexiveAddress,
    /// The nonce says the server offers a choice of password algorithm and no
    /// PASSWORD-ALGORITHMS attribute came with it, which is what an attacker
    /// stripping the choice would look like (§9.2.5).
    BidDown,
    /// The server offered password algorithms and none of them is one this
    /// implementation has.
    UnsupportedPasswordAlgorithm,
    /// The request would not fit a STUN message, which takes a credential of
    /// tens of kilobytes.
    Oversized,
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TimedOut => f.write_str("no response"),
            Self::IntegrityViolated => f.write_str("every response failed its integrity check"),
            Self::Unauthenticated => f.write_str("the server refused the credentials"),
            Self::UnknownAttribute => {
                f.write_str("a comprehension-required attribute nobody here understands")
            }
            Self::Alternate(address) => write!(f, "redirected to {address}"),
            Self::Rejected { code } => write!(f, "error response {code}"),
            Self::NoReflexiveAddress => f.write_str("a success response with no address in it"),
            Self::BidDown => f.write_str("the nonce promises password algorithms that are missing"),
            Self::UnsupportedPasswordAlgorithm => {
                f.write_str("no password algorithm in common with the server")
            }
            Self::Oversized => f.write_str("the request does not fit a message"),
        }
    }
}

impl core::error::Error for Failure {}

/// What a 401 or a 438 asked for.
#[derive(Clone)]
struct Challenge {
    realm: Vec<u8>,
    nonce: Vec<u8>,
    /// The PASSWORD-ALGORITHMS attribute verbatim, which the retry has to echo
    /// byte for byte (§9.2.4).
    algorithms: Option<Vec<u8>>,
    algorithm: PasswordAlgorithm,
}

/// The key an integrity attribute is computed under.
#[derive(Clone)]
pub(crate) enum Key {
    Md5([u8; 16]),
    Sha256([u8; 32]),
}

impl Key {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Md5(key) => key,
            Self::Sha256(key) => key,
        }
    }

    /// Overwrite the key, with the same best effort [`Password`] makes.
    fn wipe(&mut self) {
        match self {
            Self::Md5(key) => key.fill(0),
            Self::Sha256(key) => key.fill(0),
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// The key is as good as the password in its realm (§9.2.2), so every copy of
/// it goes the way the password does.
impl Drop for Key {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Waiting,
    Challenged,
    Done,
}

/// A binding transaction.
pub struct BindingClient {
    config: BindingConfig,
    state: State,
    datagram: Vec<u8>,
    transaction: Option<TransactionId>,
    key: Option<Key>,
    sends: u32,
    deadline: Option<Instant>,
    expiring: bool,
    integrity_violated: bool,
    challenge: Option<Challenge>,
    challenges: u32,
    mapped: Option<SocketAddr>,
}

impl BindingClient {
    /// A client that has not asked anything yet.
    #[must_use]
    pub fn new(config: BindingConfig) -> Self {
        Self {
            config,
            state: State::Idle,
            datagram: Vec::new(),
            transaction: None,
            key: None,
            sends: 0,
            deadline: None,
            expiring: false,
            integrity_violated: false,
            challenge: None,
            challenges: 0,
            mapped: None,
        }
    }

    /// Begin, with a transaction id the caller drew.
    ///
    /// "The first request from the client to the server [...] MUST omit the
    /// USERNAME, USERHASH, MESSAGE-INTEGRITY, MESSAGE-INTEGRITY-SHA256, REALM,
    /// NONCE, PASSWORD-ALGORITHMS, and PASSWORD-ALGORITHM attributes" (§9.2.3.1),
    /// so this one goes out bare even when credentials are configured.
    pub fn start(&mut self, transaction: TransactionId, now: Instant) -> Progress {
        self.key = None;
        self.challenge = None;
        self.challenges = 0;
        self.mapped = None;
        self.integrity_violated = false;
        self.send(transaction, now, None)
    }

    /// Answer a challenge, with a fresh transaction id.
    ///
    /// A retry after a 401 is a new transaction, not a retransmission of the
    /// old one (§9.2.3), which is why the id comes in again.
    pub fn retry(&mut self, transaction: TransactionId, now: Instant) -> Progress {
        if self.state != State::Challenged {
            return Progress::Idle;
        }
        let Some(challenge) = self.challenge.clone() else {
            return self.fail(Failure::Unauthenticated);
        };
        let Some(credentials) = self.config.credentials.as_ref() else {
            return self.fail(Failure::Unauthenticated);
        };

        let key = derive_key(
            credentials.username.as_bytes(),
            &challenge.realm,
            credentials.password.expose(),
            challenge.algorithm,
        );
        self.integrity_violated = false;
        self.send(transaction, now, Some((challenge, key)))
    }

    /// Take a datagram that arrived on the socket.
    ///
    /// Anything that is not this transaction's response comes back `Idle`,
    /// including a datagram that is not STUN at all, so a caller sharing the
    /// socket with RTP can hand over whatever it did not recognise.
    pub fn on_datagram(&mut self, datagram: &[u8]) -> Progress {
        if self.state != State::Waiting {
            return Progress::Idle;
        }
        let Ok(message) = Message::parse(datagram) else {
            return Progress::Idle;
        };
        if message.method() != Method::BINDING
            || !message.class().is_response()
            || Some(message.transaction_id()) != self.transaction
        {
            return Progress::Idle;
        }
        if message.verify_fingerprint() == Integrity::Invalid {
            return Progress::Idle;
        }
        if message.check_comprehension().is_err() {
            return self.fail(Failure::UnknownAttribute);
        }

        // 401 and 438 are answered before the integrity check, because the
        // server is allowed to send them unsigned: it has no key to sign the
        // first one with, and the second one says the key material is stale
        // (§9.2.4).
        if message.class() == Class::Error
            && let Some(error) = message.error_code()
            && matches!(
                error.code(),
                error_code::UNAUTHENTICATED | error_code::STALE_NONCE
            )
        {
            return self.on_challenge(&message);
        }
        // "If the response is an error response with an error code of 400
        // (Bad Request) and does not contain either the MESSAGE-INTEGRITY or
        // MESSAGE-INTEGRITY-SHA256 attribute, then the response MUST be
        // discarded, as if it were never received" (§9.2.5): the request
        // goes on being retransmitted. That is the long-term mechanism's
        // rule; without credentials a 400 fails the request (§6.3.4)
        if self.config.credentials.is_some() && is_unsigned_bad_request(&message) {
            return Progress::Idle;
        }

        if let Some(key) = self.key.as_ref()
            && !response_is_authentic(&message, key)
        {
            self.integrity_violated = true;
            return Progress::Idle;
        }

        match message.class() {
            Class::Success => match message
                .xor_mapped_address()
                .or_else(|| message.mapped_address())
            {
                Some(address) => {
                    self.state = State::Done;
                    self.deadline = None;
                    self.mapped = Some(address);
                    Progress::Mapped(address)
                }
                None => self.fail(Failure::NoReflexiveAddress),
            },
            Class::Error => {
                let Some(error) = message.error_code() else {
                    return self.fail(Failure::Rejected { code: 0 });
                };
                match error.code() {
                    error_code::TRY_ALTERNATE => match message.alternate_server() {
                        Some(address) => self.fail(Failure::Alternate(address)),
                        None => self.fail(Failure::Rejected {
                            code: error_code::TRY_ALTERNATE,
                        }),
                    },
                    error_code::UNKNOWN_ATTRIBUTE => self.fail(Failure::UnknownAttribute),
                    code => self.fail(Failure::Rejected { code }),
                }
            }
            Class::Request | Class::Indication => Progress::Idle,
        }
    }

    /// Take the passing of time.
    ///
    /// Call it when `deadline` has arrived; calling it earlier is harmless and
    /// answers `Idle`.
    pub fn on_timeout(&mut self, now: Instant) -> Progress {
        if self.state != State::Waiting {
            return Progress::Idle;
        }
        let Some(deadline) = self.deadline else {
            return Progress::Idle;
        };
        if now < deadline {
            return Progress::Idle;
        }
        if self.expiring {
            let reason = if self.integrity_violated {
                Failure::IntegrityViolated
            } else {
                Failure::TimedOut
            };
            return self.fail(reason);
        }
        self.arm(now);
        Progress::Transmit
    }

    /// When the next retransmission or the timeout is due.
    #[must_use]
    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The message to put on the wire.
    #[must_use]
    pub fn datagram(&self) -> &[u8] {
        &self.datagram
    }

    /// The transaction id in flight.
    #[must_use]
    pub const fn transaction_id(&self) -> Option<TransactionId> {
        self.transaction
    }

    /// The address the server said we appear from, once it has said it.
    #[must_use]
    pub const fn mapped_address(&self) -> Option<SocketAddr> {
        self.mapped
    }

    /// The realm of a challenge waiting to be answered.
    #[must_use]
    pub fn realm(&self) -> Option<&[u8]> {
        self.challenge.as_ref().map(|challenge| &*challenge.realm)
    }

    fn on_challenge(&mut self, message: &Message<'_>) -> Progress {
        if self.config.credentials.is_none() || self.challenges >= MAX_CHALLENGES {
            return self.fail(Failure::Unauthenticated);
        }
        let (Some(realm), Some(nonce)) = (message.realm(), message.nonce()) else {
            return self.fail(Failure::Unauthenticated);
        };

        let offers_algorithms = message.password_algorithms().is_some();
        if let Some(features) = security_features(nonce) {
            let promised = features
                .first()
                .is_some_and(|byte| byte & FEATURE_PASSWORD_ALGORITHMS != 0);
            if promised && !offers_algorithms {
                return self.fail(Failure::BidDown);
            }
        }

        let algorithm = if offers_algorithms {
            let chosen = message
                .offered_password_algorithms()
                .find_map(PasswordAlgorithm::from_code);
            match chosen {
                Some(algorithm) => algorithm,
                None => return self.fail(Failure::UnsupportedPasswordAlgorithm),
            }
        } else {
            PasswordAlgorithm::Md5
        };

        // "The client MUST NOT perform this retry if it is not changing the
        // USERNAME, USERHASH, REALM, or its associated password from the
        // previous attempt" (§9.2.5): a second 401 in the same realm is the
        // server saying the password is wrong, not asking again.
        if let Some(previous) = &self.challenge {
            if previous.realm == realm && previous.nonce == nonce {
                return self.fail(Failure::Unauthenticated);
            }
            if previous.realm == realm && self.key.is_some() && !is_stale_nonce(message) {
                return self.fail(Failure::Unauthenticated);
            }
        }

        self.challenge = Some(Challenge {
            realm: realm.to_vec(),
            nonce: nonce.to_vec(),
            algorithms: message.password_algorithms().map(<[u8]>::to_vec),
            algorithm,
        });
        self.challenges += 1;
        self.state = State::Challenged;
        self.deadline = None;
        Progress::Challenged
    }

    fn send(
        &mut self,
        transaction: TransactionId,
        now: Instant,
        authenticated: Option<(Challenge, Key)>,
    ) -> Progress {
        let built = match &authenticated {
            Some((challenge, key)) => self.build(transaction, Some((challenge, key))),
            None => self.build(transaction, None),
        };
        let Ok(datagram) = built else {
            return self.fail(Failure::Oversized);
        };

        self.datagram = datagram;
        self.transaction = Some(transaction);
        self.key = authenticated.map(|(_, key)| key);
        self.state = State::Waiting;
        self.sends = 0;
        self.expiring = false;
        self.arm(now);
        Progress::Transmit
    }

    fn build(
        &self,
        transaction: TransactionId,
        authenticated: Option<(&Challenge, &Key)>,
    ) -> Result<Vec<u8>, BuildError> {
        let mut builder = MessageBuilder::new(Class::Request, Method::BINDING, transaction);
        if let Some(software) = &self.config.software {
            builder.add(AttributeType::SOFTWARE, software.as_bytes())?;
        }
        if let Some((challenge, key)) = authenticated {
            let username = self
                .config
                .credentials
                .as_ref()
                .map_or("", LongTermCredentials::username);
            builder.add(AttributeType::USERNAME, username.as_bytes())?;
            builder.add(AttributeType::REALM, &challenge.realm)?;
            builder.add(AttributeType::NONCE, &challenge.nonce)?;
            if let Some(algorithms) = &challenge.algorithms {
                builder.add(AttributeType::PASSWORD_ALGORITHMS, algorithms)?;
                let mut chosen = Vec::from(challenge.algorithm.code().to_be_bytes());
                chosen.extend_from_slice(&0_u16.to_be_bytes());
                builder.add(AttributeType::PASSWORD_ALGORITHM, &chosen)?;
                // "If the response contains a PASSWORD-ALGORITHMS attribute,
                // all the subsequent requests MUST be authenticated using
                // MESSAGE-INTEGRITY-SHA256 only" (§9.2.5)
                builder.add_message_integrity_sha256(key.as_bytes())?;
            } else {
                // no choice offered, so the server is either RFC 5389 or
                // treating the request as MD5, and both want the SHA-1 one
                builder.add_message_integrity(key.as_bytes())?;
            }
        }
        if self.config.fingerprint {
            builder.add_fingerprint()?;
        }
        Ok(builder.finish())
    }

    /// Count a send and set the deadline that follows it.
    ///
    /// The gap after the nth request is `RTO * 2^(n-1)`, and after the last
    /// one it is `Rm * RTO` measured against the initial RTO rather than the
    /// doubled one: with the defaults that is requests at 0, 500, 1500, 3500,
    /// 7500, 15500 and 31500 ms and a timeout at 39500 (§6.2.1).
    fn arm(&mut self, now: Instant) {
        self.sends += 1;
        let wait = if self.sends < self.config.rc {
            let steps = (self.sends - 1).min(16);
            self.config.rto.checked_mul(1 << steps)
        } else {
            self.expiring = true;
            self.config.rto.checked_mul(self.config.rm)
        };
        let wait = wait.unwrap_or(MAX_INTERVAL).min(MAX_INTERVAL);
        self.deadline = now.checked_add(wait);
    }

    fn fail(&mut self, reason: Failure) -> Progress {
        self.state = State::Done;
        self.deadline = None;
        Progress::Failed(reason)
    }
}

impl fmt::Debug for BindingClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingClient")
            .field("transaction", &self.transaction)
            .field("sends", &self.sends)
            .field("mapped", &self.mapped)
            .finish_non_exhaustive()
    }
}

/// Whether the response carries a message-integrity attribute that checks out.
///
/// "The client looks for the MESSAGE-INTEGRITY or MESSAGE-INTEGRITY-SHA256
/// attribute in the response (either success or failure). If present, the
/// client computes the message integrity over the response [...] If the value
/// does not match, or if both [...] are absent" the response is discarded
/// (§9.2.5). Absent counts as a failure, not as an excuse.
pub(crate) fn response_is_authentic(message: &Message<'_>, key: &Key) -> bool {
    match message.verify_integrity_sha256(key.as_bytes()) {
        Integrity::Valid => return true,
        Integrity::Invalid => return false,
        Integrity::Absent => {}
    }
    message.verify_integrity(key.as_bytes()) == Integrity::Valid
}

/// A 400 with neither integrity attribute, which a client discards rather
/// than acting on (§9.2.5).
pub(crate) fn is_unsigned_bad_request(message: &Message<'_>) -> bool {
    message.class() == Class::Error
        && message
            .error_code()
            .is_some_and(|error| error.code() == error_code::BAD_REQUEST)
        && !message.has_integrity()
}

fn is_stale_nonce(message: &Message<'_>) -> bool {
    message
        .error_code()
        .is_some_and(|error| error.code() == error_code::STALE_NONCE)
}

/// `MD5(username ":" realm ":" password)`, or the SHA-256 of the same string
/// where the server asked for that instead (§9.2.2, §18.5.1).
pub(crate) fn derive_key(
    username: &[u8],
    realm: &[u8],
    password: &[u8],
    algorithm: PasswordAlgorithm,
) -> Key {
    let mut input = Vec::with_capacity(username.len() + realm.len() + password.len() + 2);
    input.extend_from_slice(username);
    input.push(b':');
    input.extend_from_slice(realm);
    input.push(b':');
    input.extend_from_slice(password);

    let key = match algorithm {
        PasswordAlgorithm::Md5 => Key::Md5(Md5::digest(&input)),
        PasswordAlgorithm::Sha256 => Key::Sha256(Sha256::digest(&input)),
    };

    // the password spent a moment in a buffer of our own making
    input.fill(0);
    compiler_fence(Ordering::SeqCst);
    key
}

/// The twenty-four security-feature bits a nonce cookie carries, if the nonce
/// has one (§9.2).
pub(crate) fn security_features(nonce: &[u8]) -> Option<[u8; 3]> {
    let quad = nonce.strip_prefix(NONCE_COOKIE)?.get(..4)?;
    let mut bits = 0_u32;
    for byte in quad {
        bits = (bits << 6) | u32::from(base64_digit(*byte)?);
    }
    Some([
        u8::try_from((bits >> 16) & 0xff).unwrap_or_default(),
        u8::try_from((bits >> 8) & 0xff).unwrap_or_default(),
        u8::try_from(bits & 0xff).unwrap_or_default(),
    ])
}

const fn base64_digit(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::{Duration, Instant};

    use super::{
        BindingClient, BindingConfig, Failure, Key, LongTermCredentials, Progress, derive_key,
        security_features,
    };
    use crate::stun::attribute::{AttributeType, PasswordAlgorithm};
    use crate::stun::builder::MessageBuilder;
    use crate::stun::message::{Class, Integrity, Message, Method, TransactionId};

    fn identifier(seed: u8) -> TransactionId {
        TransactionId::new([seed; 12])
    }

    fn address(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    fn client() -> BindingClient {
        BindingClient::new(BindingConfig::default())
    }

    /// Walk the whole retransmission schedule, answering nothing.
    fn run_out(client: &mut BindingClient) -> Progress {
        loop {
            let Some(deadline) = client.deadline() else {
                return Progress::Idle;
            };
            match client.on_timeout(deadline) {
                Progress::Transmit => {}
                other => return other,
            }
        }
    }

    fn authenticated_client() -> BindingClient {
        BindingClient::new(BindingConfig {
            credentials: Some(LongTermCredentials::new("user", "pass")),
            ..BindingConfig::default()
        })
    }

    fn success(transaction: TransactionId, mapped: &str) -> Vec<u8> {
        let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, transaction);
        builder
            .add_xor_address(AttributeType::XOR_MAPPED_ADDRESS, address(mapped))
            .unwrap();
        builder.finish()
    }

    fn challenge(transaction: TransactionId, nonce: &[u8], code: u16) -> Vec<u8> {
        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, transaction);
        builder.add_error_code(code, b"Unauthenticated").unwrap();
        builder.add(AttributeType::REALM, b"sipral.test").unwrap();
        builder.add(AttributeType::NONCE, nonce).unwrap();
        builder.finish()
    }

    #[test]
    fn the_first_request_carries_no_credentials() {
        let mut client = authenticated_client();
        assert_eq!(
            client.start(identifier(1), Instant::now()),
            Progress::Transmit
        );

        let message = Message::parse(client.datagram()).unwrap();
        assert_eq!(message.class(), Class::Request);
        assert_eq!(message.method(), Method::BINDING);
        assert_eq!(message.username(), None);
        assert_eq!(message.realm(), None);
        assert!(!message.has_integrity());
        assert_eq!(message.verify_fingerprint(), Integrity::Valid);
    }

    #[test]
    fn a_success_response_reports_the_reflexive_address() {
        let mut client = client();
        client.start(identifier(1), Instant::now());
        let response = success(identifier(1), "198.51.100.7:53412");

        assert_eq!(
            client.on_datagram(&response),
            Progress::Mapped(address("198.51.100.7:53412"))
        );
        assert_eq!(client.mapped_address(), Some(address("198.51.100.7:53412")));
        assert_eq!(client.deadline(), None);
    }

    #[test]
    fn a_response_to_some_other_transaction_is_not_ours() {
        let mut client = client();
        client.start(identifier(1), Instant::now());
        let response = success(identifier(2), "198.51.100.7:53412");
        assert_eq!(client.on_datagram(&response), Progress::Idle);
    }

    #[test]
    fn something_that_is_not_stun_at_all_is_not_ours() {
        let mut client = client();
        client.start(identifier(1), Instant::now());
        assert_eq!(
            client.on_datagram(&[0x80, 0x08, 0, 0, 0, 0]),
            Progress::Idle
        );
        assert_eq!(client.on_datagram(&[]), Progress::Idle);
    }

    #[test]
    fn a_success_response_with_no_address_fails_the_transaction() {
        let mut client = client();
        client.start(identifier(1), Instant::now());
        let response = MessageBuilder::new(Class::Success, Method::BINDING, identifier(1)).finish();
        assert_eq!(
            client.on_datagram(&response),
            Progress::Failed(Failure::NoReflexiveAddress)
        );
    }

    #[test]
    fn the_retransmission_schedule_is_the_one_in_the_rfc() {
        let start = Instant::now();
        let mut client = client();
        assert_eq!(client.start(identifier(1), start), Progress::Transmit);

        let expected = [500_u64, 1500, 3500, 7500, 15500, 31500];
        let mut at = start;
        for millis in expected {
            let deadline = start + Duration::from_millis(millis);
            assert_eq!(client.deadline(), Some(deadline));
            // a deadline that has not arrived changes nothing
            let early = deadline.checked_sub(Duration::from_millis(1)).unwrap();
            assert_eq!(client.on_timeout(early), Progress::Idle);
            assert_eq!(client.on_timeout(deadline), Progress::Transmit);
            at = deadline;
        }

        // seven requests are out; the last wait is sixteen times the initial
        // RTO, not sixteen times the doubled one
        assert_eq!(client.deadline(), Some(at + Duration::from_millis(8000)));
        assert_eq!(
            client.deadline(),
            Some(start + Duration::from_millis(39_500))
        );
        assert_eq!(
            client.on_timeout(start + Duration::from_millis(39_500)),
            Progress::Failed(Failure::TimedOut)
        );
    }

    #[test]
    fn a_retransmission_is_the_same_bytes_as_the_first_request() {
        let start = Instant::now();
        let mut client = client();
        client.start(identifier(1), start);
        let first = client.datagram().to_vec();

        client.on_timeout(start + Duration::from_millis(500));
        assert_eq!(client.datagram(), first.as_slice());
    }

    #[test]
    fn a_timed_out_transaction_stays_timed_out() {
        let start = Instant::now();
        let mut client = client();
        client.start(identifier(1), start);
        assert_eq!(run_out(&mut client), Progress::Failed(Failure::TimedOut));
        let over = start + Duration::from_secs(60);
        assert_eq!(client.on_timeout(over), Progress::Idle);
        assert_eq!(
            client.on_datagram(&success(identifier(1), "198.51.100.7:1")),
            Progress::Idle
        );
    }

    #[test]
    fn a_challenge_is_answered_with_the_long_term_key() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);

        assert_eq!(
            client.on_datagram(&challenge(identifier(1), b"nonce-one", 401)),
            Progress::Challenged
        );
        assert_eq!(client.realm(), Some(b"sipral.test".as_slice()));
        assert_eq!(client.deadline(), None);

        assert_eq!(
            client.retry(identifier(2), start + Duration::from_millis(10)),
            Progress::Transmit
        );

        let message = Message::parse(client.datagram()).unwrap();
        assert_eq!(message.transaction_id(), identifier(2));
        assert_eq!(message.username(), Some(b"user".as_slice()));
        assert_eq!(message.realm(), Some(b"sipral.test".as_slice()));
        assert_eq!(message.nonce(), Some(b"nonce-one".as_slice()));

        // MD5("user:sipral.test:pass") is the key, and the check is over the
        // message as it stands
        let key = super::derive_key(
            b"user",
            b"sipral.test",
            b"pass",
            crate::stun::attribute::PasswordAlgorithm::Md5,
        );
        assert_eq!(message.verify_integrity(key.as_bytes()), Integrity::Valid);
        assert_eq!(message.verify_fingerprint(), Integrity::Valid);
    }

    #[test]
    fn a_challenge_with_no_credentials_configured_ends_the_transaction() {
        let mut client = client();
        client.start(identifier(1), Instant::now());
        assert_eq!(
            client.on_datagram(&challenge(identifier(1), b"nonce-one", 401)),
            Progress::Failed(Failure::Unauthenticated)
        );
    }

    #[test]
    fn the_same_challenge_twice_is_a_refusal_rather_than_a_loop() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);
        client.on_datagram(&challenge(identifier(1), b"nonce-one", 401));
        client.retry(identifier(2), start);

        assert_eq!(
            client.on_datagram(&challenge(identifier(2), b"nonce-one", 401)),
            Progress::Failed(Failure::Unauthenticated)
        );
    }

    #[test]
    fn a_stale_nonce_is_answered_with_the_new_one() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);
        client.on_datagram(&challenge(identifier(1), b"nonce-one", 401));
        client.retry(identifier(2), start);

        assert_eq!(
            client.on_datagram(&challenge(identifier(2), b"nonce-two", 438)),
            Progress::Challenged
        );
        assert_eq!(client.retry(identifier(3), start), Progress::Transmit);

        let message = Message::parse(client.datagram()).unwrap();
        assert_eq!(message.nonce(), Some(b"nonce-two".as_slice()));
    }

    #[test]
    fn an_endless_run_of_stale_nonces_is_given_up_on() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);
        client.on_datagram(&challenge(identifier(1), b"nonce-one", 401));
        client.retry(identifier(2), start);

        client.on_datagram(&challenge(identifier(2), b"nonce-two", 438));
        client.retry(identifier(3), start);
        client.on_datagram(&challenge(identifier(3), b"nonce-three", 438));
        client.retry(identifier(4), start);

        assert_eq!(
            client.on_datagram(&challenge(identifier(4), b"nonce-four", 438)),
            Progress::Failed(Failure::Unauthenticated)
        );
    }

    #[test]
    fn a_nonce_promising_password_algorithms_without_them_is_a_bid_down() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);

        // the cookie plus "gAAA", which is the password-algorithms bit alone
        let mut nonce = Vec::from(*b"obMatJos2gAAA");
        nonce.extend_from_slice(b"whatever");
        assert_eq!(
            client.on_datagram(&challenge(identifier(1), &nonce, 401)),
            Progress::Failed(Failure::BidDown)
        );
    }

    #[test]
    fn a_nonce_with_a_cookie_and_no_promise_is_answered_normally() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);

        let mut nonce = Vec::from(*b"obMatJos2AAAA");
        nonce.extend_from_slice(b"whatever");
        assert_eq!(
            client.on_datagram(&challenge(identifier(1), &nonce, 401)),
            Progress::Challenged
        );
    }

    #[test]
    fn an_offer_of_password_algorithms_is_echoed_and_signed_with_sha256() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);

        let offer = [0, 1, 0, 0, 0, 2, 0, 0];
        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, identifier(1));
        builder.add_error_code(401, b"Unauthenticated").unwrap();
        builder.add(AttributeType::REALM, b"sipral.test").unwrap();
        builder
            .add(AttributeType::NONCE, b"obMatJos2gAAAnonce")
            .unwrap();
        builder
            .add(AttributeType::PASSWORD_ALGORITHMS, &offer)
            .unwrap();
        let response = builder.finish();

        assert_eq!(client.on_datagram(&response), Progress::Challenged);
        assert_eq!(client.retry(identifier(2), start), Progress::Transmit);

        let message = Message::parse(client.datagram()).unwrap();
        assert_eq!(
            message.find(AttributeType::PASSWORD_ALGORITHMS),
            Some(offer.as_slice())
        );
        assert_eq!(
            message.find(AttributeType::PASSWORD_ALGORITHM),
            Some([0, 1, 0, 0].as_slice())
        );
        assert!(message.find(AttributeType::MESSAGE_INTEGRITY).is_none());

        let key = super::derive_key(
            b"user",
            b"sipral.test",
            b"pass",
            crate::stun::attribute::PasswordAlgorithm::Md5,
        );
        assert_eq!(
            message.verify_integrity_sha256(key.as_bytes()),
            Integrity::Valid
        );
    }

    #[test]
    fn an_offer_of_nothing_we_have_ends_the_transaction() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);

        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, identifier(1));
        builder.add_error_code(401, b"Unauthenticated").unwrap();
        builder.add(AttributeType::REALM, b"sipral.test").unwrap();
        builder
            .add(AttributeType::NONCE, b"obMatJos2gAAAnonce")
            .unwrap();
        builder
            .add(AttributeType::PASSWORD_ALGORITHMS, &[0, 9, 0, 0])
            .unwrap();
        let response = builder.finish();

        assert_eq!(
            client.on_datagram(&response),
            Progress::Failed(Failure::UnsupportedPasswordAlgorithm)
        );
    }

    #[test]
    fn a_signed_response_with_the_wrong_key_is_discarded_and_the_timeout_says_so() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);
        client.on_datagram(&challenge(identifier(1), b"nonce-one", 401));
        client.retry(identifier(2), start);

        let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, identifier(2));
        builder
            .add_xor_address(
                AttributeType::XOR_MAPPED_ADDRESS,
                address("198.51.100.7:53412"),
            )
            .unwrap();
        builder.add_message_integrity(b"not the key").unwrap();
        let forged = builder.finish();

        assert_eq!(client.on_datagram(&forged), Progress::Idle);
        assert_eq!(client.mapped_address(), None);

        assert_eq!(
            run_out(&mut client),
            Progress::Failed(Failure::IntegrityViolated)
        );
    }

    #[test]
    fn a_signed_response_with_the_right_key_is_believed() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);
        client.on_datagram(&challenge(identifier(1), b"nonce-one", 401));
        client.retry(identifier(2), start);

        let key = super::derive_key(
            b"user",
            b"sipral.test",
            b"pass",
            crate::stun::attribute::PasswordAlgorithm::Md5,
        );
        let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, identifier(2));
        builder
            .add_xor_address(
                AttributeType::XOR_MAPPED_ADDRESS,
                address("198.51.100.7:53412"),
            )
            .unwrap();
        builder.add_message_integrity(key.as_bytes()).unwrap();
        builder.add_fingerprint().unwrap();
        let response = builder.finish();

        assert_eq!(
            client.on_datagram(&response),
            Progress::Mapped(address("198.51.100.7:53412"))
        );
    }

    #[test]
    fn an_unsigned_response_to_a_signed_request_is_discarded() {
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);
        client.on_datagram(&challenge(identifier(1), b"nonce-one", 401));
        client.retry(identifier(2), start);

        assert_eq!(
            client.on_datagram(&success(identifier(2), "198.51.100.7:53412")),
            Progress::Idle
        );
    }

    #[test]
    fn a_broken_fingerprint_means_the_datagram_was_never_ours() {
        let start = Instant::now();
        let mut client = client();
        client.start(identifier(1), start);

        let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, identifier(1));
        builder
            .add_xor_address(
                AttributeType::XOR_MAPPED_ADDRESS,
                address("198.51.100.7:53412"),
            )
            .unwrap();
        builder.add_fingerprint().unwrap();
        let mut response = builder.finish();
        let last = response.len() - 1;
        response[last] ^= 0xff;

        assert_eq!(client.on_datagram(&response), Progress::Idle);
    }

    #[test]
    fn a_try_alternate_reports_where_to_go_instead() {
        let start = Instant::now();
        let mut client = client();
        client.start(identifier(1), start);

        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, identifier(1));
        builder.add_error_code(300, b"Try Alternate").unwrap();
        builder
            .add_address(
                AttributeType::ALTERNATE_SERVER,
                address("198.51.100.9:3478"),
            )
            .unwrap();
        let response = builder.finish();

        assert_eq!(
            client.on_datagram(&response),
            Progress::Failed(Failure::Alternate(address("198.51.100.9:3478")))
        );
    }

    #[test]
    fn an_error_this_client_does_not_act_on_is_reported_with_its_code() {
        let start = Instant::now();
        let mut client = client();
        client.start(identifier(1), start);

        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, identifier(1));
        builder.add_error_code(500, b"Server Error").unwrap();
        let response = builder.finish();

        assert_eq!(
            client.on_datagram(&response),
            Progress::Failed(Failure::Rejected { code: 500 })
        );
    }

    #[test]
    fn an_unsigned_400_is_discarded_and_the_transaction_runs_on() {
        // "If the response is an error response with an error code of 400
        // (Bad Request) and does not contain either the MESSAGE-INTEGRITY or
        // MESSAGE-INTEGRITY-SHA256 attribute, then the response MUST be
        // discarded, as if it were never received" (RFC 8489 §9.2.5)
        let start = Instant::now();
        let mut client = authenticated_client();
        client.start(identifier(1), start);

        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, identifier(1));
        builder.add_error_code(400, b"Bad Request").unwrap();
        assert_eq!(client.on_datagram(&builder.finish()), Progress::Idle);
        assert!(client.deadline().is_some(), "the transaction was ended");

        let response = success(identifier(1), "198.51.100.7:53412");
        assert_eq!(
            client.on_datagram(&response),
            Progress::Mapped(address("198.51.100.7:53412"))
        );
    }

    #[test]
    fn without_credentials_a_400_ends_the_transaction_at_once() {
        // §9.2.5 is the long-term credential mechanism's; a client that has
        // no credentials is not running it, and for a plain Binding request
        // "if the error code is 400 through 499, the client declares the
        // transaction failed" (§6.3.4). Discarding it would only have a
        // server's refusal reported as a timeout, seconds later, and would
        // protect nothing: nothing an unauthenticated exchange receives can
        // be told from what anyone on the path writes
        let start = Instant::now();
        let mut client = client();
        client.start(identifier(1), start);

        let mut builder = MessageBuilder::new(Class::Error, Method::BINDING, identifier(1));
        builder.add_error_code(400, b"Bad Request").unwrap();
        assert_eq!(
            client.on_datagram(&builder.finish()),
            Progress::Failed(Failure::Rejected { code: 400 })
        );
    }

    #[test]
    fn a_long_term_key_is_overwritten_when_it_goes() {
        // MD5(username ":" realm ":" password) is as good as the password to
        // whoever holds it: it signs requests in that realm for as long as
        // the password stays the same (§9.2.2). Every copy of one — the
        // client's, a TURN allocation's, the clone a response is checked
        // with — has to be wiped as it is dropped, the way the password is
        assert!(
            core::mem::needs_drop::<Key>(),
            "a derived key is left in memory when it is dropped"
        );
        let mut key = derive_key(b"user", b"realm", b"pass", PasswordAlgorithm::Md5);
        key.wipe();
        assert_eq!(key.as_bytes(), [0_u8; 16]);
        let mut key = derive_key(b"user", b"realm", b"pass", PasswordAlgorithm::Sha256);
        key.wipe();
        assert_eq!(key.as_bytes(), [0_u8; 32]);
    }

    #[test]
    fn an_unknown_comprehension_required_attribute_in_a_response_ends_it() {
        let start = Instant::now();
        let mut client = client();
        client.start(identifier(1), start);

        let mut builder = MessageBuilder::new(Class::Success, Method::BINDING, identifier(1));
        builder
            .add_xor_address(
                AttributeType::XOR_MAPPED_ADDRESS,
                address("198.51.100.7:53412"),
            )
            .unwrap();
        builder.add(AttributeType::new(0x4000), b"?").unwrap();
        let response = builder.finish();

        assert_eq!(
            client.on_datagram(&response),
            Progress::Failed(Failure::UnknownAttribute)
        );
    }

    #[test]
    fn retrying_without_a_challenge_does_nothing() {
        let mut client = client();
        assert_eq!(client.retry(identifier(1), Instant::now()), Progress::Idle);
        client.start(identifier(1), Instant::now());
        assert_eq!(client.retry(identifier(2), Instant::now()), Progress::Idle);
    }

    #[test]
    fn the_software_attribute_goes_in_when_it_is_configured() {
        let mut client = BindingClient::new(BindingConfig {
            software: Some("sipral".to_owned()),
            fingerprint: false,
            ..BindingConfig::default()
        });
        client.start(identifier(1), Instant::now());

        let message = Message::parse(client.datagram()).unwrap();
        assert_eq!(message.software(), Some(b"sipral".as_slice()));
        assert_eq!(message.verify_fingerprint(), Integrity::Absent);
    }

    #[test]
    fn the_nonce_cookie_decodes_the_security_features() {
        assert_eq!(security_features(b"obMatJos2AAAAnonce"), Some([0, 0, 0]));
        assert_eq!(security_features(b"obMatJos2gAAAnonce"), Some([0x80, 0, 0]));
        assert_eq!(security_features(b"obMatJos2QAAAnonce"), Some([0x40, 0, 0]));
        assert_eq!(security_features(b"obMatJos2wAAAnonce"), Some([0xc0, 0, 0]));
        assert_eq!(
            security_features(b"obMatJos2////nonce"),
            Some([0xff, 0xff, 0xff])
        );
    }

    #[test]
    fn a_nonce_without_the_cookie_has_no_features() {
        assert_eq!(security_features(b"plain-nonce"), None);
        assert_eq!(security_features(b"obMatJos2"), None);
        assert_eq!(security_features(b"obMatJos2!!!!"), None);
    }
}
