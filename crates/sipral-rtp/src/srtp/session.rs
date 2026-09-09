// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Turning an RTP packet into an SRTP one and back, per RFC 3711 §3.3 and
//! §3.4.
//!
//! Both directions work in the buffer the caller already owns: protecting
//! encrypts the payload where it lies and writes the tag after it, and
//! unprotecting verifies, decrypts in place and returns the shorter length.
//! That is the same contract the rest of the crate keeps — nothing here
//! allocates a packet.

use super::cipher::{self, Counter, Exhausted, F8};
use super::index::{Estimate, Receiving, Replay, Sending};
use super::kdf::{self, Master, Rate, Session};
use super::sha1;

/// The RTP fixed header, before any CSRC list (RFC 3550 §5.1).
const RTP_HEADER: usize = 12;

/// What SRTCP encrypts from: "from the ninth (9) octet to the end of the
/// compound packet" (§3.4), the first eight being the report header the
/// receiver needs in clear to find the sender.
const RTCP_HEADER: usize = 8;

/// The E flag and the 31-bit index SRTCP appends (§3.4).
const RTCP_INDEX: usize = 4;

/// §3.4: the E flag is the most significant bit of the index word.
const RTCP_ENCRYPTED: u32 = 0x8000_0000;

/// §9.2: "This limit is fixed to 2^48 SRTP packets for an SRTP stream."
const RTP_LIMIT: u64 = 1 << 48;

/// §9.2: "and 2^31 SRTCP packets".
const RTCP_LIMIT: u64 = 1 << 31;

/// The transforms RFC 4568 §6.2 names, which are the ones a peer can offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    /// `AES_CM_128_HMAC_SHA1_80`: counter mode with an eighty-bit tag. The
    /// default, and the one every implementation has.
    AesCm80,
    /// `AES_CM_128_HMAC_SHA1_32`: the same cipher with a thirty-two-bit tag,
    /// for links where ten octets a packet is worth arguing about.
    AesCm32,
    /// `F8_128_HMAC_SHA1_80`: f8 mode, which is what 3GPP asks for.
    AesF8,
}

impl Suite {
    /// The authentication tag length on SRTP packets, `n_tag`.
    #[must_use]
    pub const fn tag(self) -> usize {
        match self {
            Self::AesCm80 | Self::AesF8 => 10,
            Self::AesCm32 => 4,
        }
    }

    /// The tag length on SRTCP packets.
    ///
    /// §5.2: "for SRTCP, the pre-defined HMAC-SHA1 MUST NOT be applied with a
    /// value of n_tag, nor n_a, that are smaller than these defaults" — so
    /// the short suite shortens SRTP tags and leaves SRTCP's alone.
    #[must_use]
    pub const fn rtcp_tag(self) -> usize {
        10
    }

    /// The name this suite carries in an `a=crypto` line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AesCm80 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm32 => "AES_CM_128_HMAC_SHA1_32",
            Self::AesF8 => "F8_128_HMAC_SHA1_80",
        }
    }

    /// The suite an `a=crypto` line names, if it is one we implement.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [Self::AesCm80, Self::AesCm32, Self::AesF8]
            .into_iter()
            .find(|suite| suite.name().eq_ignore_ascii_case(name))
    }
}

/// A master key identifier, which RFC 4568 §6.1 carries as `MKI:length`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mki {
    value: u128,
    length: usize,
}

impl Mki {
    /// An identifier of `length` octets. RFC 4568 allows one to 128; anything
    /// wider than the value it has to hold is refused here rather than
    /// silently truncated.
    #[must_use]
    pub fn new(value: u128, length: usize) -> Option<Self> {
        (1..=16).contains(&length).then_some(Self { value, length })
    }

    const fn len(self) -> usize {
        self.length
    }

    fn write(self, out: &mut [u8]) {
        let bytes = self.value.to_be_bytes();
        if let Some(tail) = bytes.get(16 - self.length..)
            && let Some(slot) = out.get_mut(..self.length)
        {
            slot.copy_from_slice(tail);
        }
    }

    fn matches(self, bytes: &[u8]) -> bool {
        let mut value = [0_u8; 16];
        if let Some(slot) = value.get_mut(16 - self.length..) {
            slot.copy_from_slice(bytes);
        }
        u128::from_be_bytes(value) == self.value
    }
}

/// What the two sides agreed to do, beyond which cipher to use.
///
/// The three booleans are RFC 4568 §6.3.2 and §6.3.3, whose defaults are what
/// `Policy::new` sets: everything encrypted, everything authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// The transform.
    pub suite: Suite,
    /// How often session keys are re-derived (§4.3.1).
    pub rate: Rate,
    /// `UNENCRYPTED_SRTP` clears this.
    pub encrypt_rtp: bool,
    /// `UNENCRYPTED_SRTCP` clears this.
    pub encrypt_rtcp: bool,
    /// `UNAUTHENTICATED_SRTP` clears this. It does not reach SRTCP, whose tag
    /// §3.4 makes REQUIRED.
    pub authenticate_rtp: bool,
    /// The master key identifier, when the peer asked for one.
    pub mki: Option<Mki>,
}

impl Policy {
    /// The defaults of RFC 4568: encrypt and authenticate everything, derive
    /// the session keys once, no master key identifier.
    #[must_use]
    pub const fn new(suite: Suite) -> Self {
        Self {
            suite,
            rate: Rate::ONCE,
            encrypt_rtp: true,
            encrypt_rtcp: true,
            authenticate_rtp: true,
            mki: None,
        }
    }

    const fn rtp_overhead(&self) -> usize {
        let tag = if self.authenticate_rtp {
            self.suite.tag()
        } else {
            0
        };
        tag + self.mki_len()
    }

    const fn rtcp_overhead(&self) -> usize {
        RTCP_INDEX + self.suite.rtcp_tag() + self.mki_len()
    }

    const fn mki_len(&self) -> usize {
        match self.mki {
            Some(mki) => mki.len(),
            None => 0,
        }
    }
}

/// Why a packet could not be protected or was refused on arrival.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpError {
    /// Shorter than the header the transform needs to read.
    TooShort {
        /// What arrived, or what was offered to protect.
        got: usize,
    },
    /// The version field is not 2, or the header claims more than is there.
    Malformed,
    /// The buffer handed in has no room for the tag and the index.
    NoRoom {
        /// Octets the protected packet needs.
        need: usize,
        /// Octets the buffer has.
        got: usize,
    },
    /// The index has already been seen, so the packet is a replay (§3.3.2).
    Replayed,
    /// The tag does not match: "AUTHENTICATION FAILURE" (§4.2).
    NotAuthentic,
    /// The identifier in the packet is not the master key we hold.
    UnknownKey,
    /// §9.2's limit is reached and key management has to be called before
    /// anything else is sent.
    KeyExhausted,
    /// A packet so long that one keystream segment cannot cover it (§4.1.1).
    TooLong,
}

impl core::fmt::Display for SrtpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort { got } => write!(f, "packet of {got} octets is too short for SRTP"),
            Self::Malformed => f.write_str("the header is not a well-formed RTP or RTCP header"),
            Self::NoRoom { need, got } => {
                write!(
                    f,
                    "the protected packet needs {need} octets, the buffer has {got}"
                )
            }
            Self::Replayed => f.write_str("the packet index has already been received"),
            Self::NotAuthentic => f.write_str("authentication failure"),
            Self::UnknownKey => f.write_str("the packet names a master key we do not hold"),
            Self::KeyExhausted => {
                f.write_str("the master key has secured as many packets as it may")
            }
            Self::TooLong => f.write_str("the packet is longer than one keystream segment"),
        }
    }
}

impl core::error::Error for SrtpError {}

impl From<Exhausted> for SrtpError {
    fn from(_: Exhausted) -> Self {
        Self::TooLong
    }
}

/// The keystream generator for one direction and one protocol.
#[expect(
    clippy::large_enum_variant,
    reason = "the difference is one AES key schedule, and there is one of these per session, not per packet"
)]
enum Keystream {
    Counter(Counter),
    F8(F8),
}

impl Keystream {
    fn new(suite: Suite, keys: &Session) -> Self {
        match suite {
            Suite::AesCm80 | Suite::AesCm32 => Self::Counter(Counter::new(&keys.encryption)),
            Suite::AesF8 => Self::F8(F8::new(&keys.encryption, &keys.salt)),
        }
    }

    fn apply(&self, iv: &[u8; cipher::BLOCK], data: &mut [u8]) -> Result<(), Exhausted> {
        match self {
            Self::Counter(counter) => counter.apply(iv, data),
            Self::F8(f8) => f8.apply(iv, data),
        }
    }
}

/// One derivation's worth of session state: the cipher, the salt the counter
/// IV needs, and the authentication key.
struct Engine {
    keystream: Keystream,
    salt: [u8; kdf::SALT],
    authentication: [u8; kdf::AUTH],
}

impl Engine {
    fn new(suite: Suite, keys: &Session) -> Self {
        Self {
            keystream: Keystream::new(suite, keys),
            salt: keys.salt,
            authentication: keys.authentication,
        }
    }

    /// §4.1.1: `IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)`.
    fn counter_iv(&self, ssrc: u32, index: u64) -> [u8; cipher::BLOCK] {
        let mut iv = [0_u8; cipher::BLOCK];
        if let Some(head) = iv.get_mut(..kdf::SALT) {
            head.copy_from_slice(&self.salt);
        }
        for (byte, value) in iv.iter_mut().skip(4).zip(ssrc.to_be_bytes()) {
            *byte ^= value;
        }
        // the index is 48 bits and sits two octets from the end, which is
        // what leaves the low sixteen bits to the block counter
        for (byte, value) in iv
            .iter_mut()
            .skip(8)
            .zip(index.to_be_bytes().into_iter().skip(2))
        {
            *byte ^= value;
        }
        iv
    }

    /// §4.1.2.2: `IV = 0x00 || M || PT || SEQ || TS || SSRC || ROC`, which is
    /// the RTP header from its second octet on, followed by the rollover
    /// counter. The header is in the IV so that changing it breaks
    /// decryption — what §9.5 calls implicit header authentication.
    fn f8_rtp_iv(header: &[u8], roc: u32) -> [u8; cipher::BLOCK] {
        let mut iv = [0_u8; cipher::BLOCK];
        if let Some(slot) = iv.get_mut(1..RTP_HEADER) {
            slot.copy_from_slice(header.get(1..RTP_HEADER).unwrap_or(&[0; RTP_HEADER - 1]));
        }
        if let Some(slot) = iv.get_mut(RTP_HEADER..) {
            slot.copy_from_slice(&roc.to_be_bytes());
        }
        iv
    }

    /// §4.1.2.3: `IV = 0..0 || E || SRTCP index || V || P || RC || PT ||
    /// length || SSRC`, the tail of which is the first eight octets of the
    /// compound packet.
    fn f8_rtcp_iv(header: &[u8], word: u32) -> [u8; cipher::BLOCK] {
        let mut iv = [0_u8; cipher::BLOCK];
        if let Some(slot) = iv.get_mut(4..RTCP_HEADER) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        if let Some(slot) = iv.get_mut(RTCP_HEADER..) {
            slot.copy_from_slice(header.get(..RTCP_HEADER).unwrap_or(&[0; RTCP_HEADER]));
        }
        iv
    }

    fn encrypt_rtp(
        &self,
        suite: Suite,
        header: &[u8],
        ssrc: u32,
        index: u64,
        roc: u32,
        payload: &mut [u8],
    ) -> Result<(), Exhausted> {
        let iv = match suite {
            Suite::AesCm80 | Suite::AesCm32 => self.counter_iv(ssrc, index),
            Suite::AesF8 => Self::f8_rtp_iv(header, roc),
        };
        self.keystream.apply(&iv, payload)
    }

    fn encrypt_rtcp(
        &self,
        suite: Suite,
        header: &[u8],
        ssrc: u32,
        index: u32,
        word: u32,
        payload: &mut [u8],
    ) -> Result<(), Exhausted> {
        let iv = match suite {
            Suite::AesCm80 | Suite::AesCm32 => self.counter_iv(ssrc, u64::from(index)),
            Suite::AesF8 => Self::f8_rtcp_iv(header, word),
        };
        self.keystream.apply(&iv, payload)
    }

    /// §4.2: `HMAC(k_a, M)` truncated to the left-most `tag` octets.
    fn tag(&self, parts: &[&[u8]], tag: usize, out: &mut [u8]) {
        let full = sha1::hmac(&self.authentication, parts);
        if let Some(slot) = out.get_mut(..tag) {
            slot.copy_from_slice(full.get(..tag).unwrap_or_default());
        }
    }
}

/// The session keys, re-derived when the key derivation rate says so.
struct Derived {
    master: Master,
    suite: Suite,
    rate: Rate,
    rtp: Engine,
    rtp_phase: u64,
    rtcp: Engine,
    rtcp_phase: u64,
}

impl Derived {
    fn new(policy: &Policy, master: Master) -> Self {
        Self {
            suite: policy.suite,
            rate: policy.rate,
            rtp: Engine::new(policy.suite, &master.rtp_session(policy.rate, 0)),
            rtp_phase: 0,
            rtcp: Engine::new(policy.suite, &master.rtcp_session(policy.rate, 0)),
            rtcp_phase: 0,
            master,
        }
    }

    fn rtp(&mut self, index: u64) -> &Engine {
        let phase = self.rate.phase_of(index);
        if phase != self.rtp_phase {
            self.rtp = Engine::new(self.suite, &self.master.rtp_session(self.rate, index));
            self.rtp_phase = phase;
        }
        &self.rtp
    }

    fn rtcp(&mut self, index: u32) -> &Engine {
        let phase = self.rate.phase_of(u64::from(index));
        if phase != self.rtcp_phase {
            self.rtcp = Engine::new(self.suite, &self.master.rtcp_session(self.rate, index));
            self.rtcp_phase = phase;
        }
        &self.rtcp
    }
}

/// The sending half of an SRTP session: one SSRC, one master key.
pub struct Protector {
    policy: Policy,
    keys: Derived,
    rtp: Sending,
    rtp_packets: u64,
    rtcp_index: u32,
    rtcp_packets: u64,
}

impl Protector {
    /// A protector for one outgoing stream.
    #[must_use]
    pub fn new(policy: Policy, master: Master) -> Self {
        Self {
            keys: Derived::new(&policy, master),
            policy,
            rtp: Sending::default(),
            rtp_packets: 0,
            rtcp_index: 0,
            rtcp_packets: 0,
        }
    }

    /// Octets a protected RTP packet is longer than the packet it came from.
    #[must_use]
    pub const fn rtp_overhead(&self) -> usize {
        self.policy.rtp_overhead()
    }

    /// Octets a protected RTCP packet is longer than the packet it came from.
    #[must_use]
    pub const fn rtcp_overhead(&self) -> usize {
        self.policy.rtcp_overhead()
    }

    /// The rollover counter, which a peer joining an ongoing session has to
    /// be told out of band (§3.3.1).
    #[must_use]
    pub const fn rollover(&self) -> u32 {
        self.rtp.rollover()
    }

    /// Protect the RTP packet occupying the first `len` octets of `packet`.
    ///
    /// The buffer has to have `rtp_overhead()` octets of room after it.
    /// Returns the length of the protected packet.
    ///
    /// # Errors
    ///
    /// Refuses a malformed header, a buffer with no room, and — the one worth
    /// handling rather than logging — a master key that has secured as many
    /// packets as §9.2 allows.
    pub fn protect_rtp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        if self.rtp_packets >= RTP_LIMIT {
            return Err(SrtpError::KeyExhausted);
        }
        let header = rtp_header_len(packet.get(..len).ok_or(SrtpError::TooShort { got: len })?)?;
        let need = len + self.policy.rtp_overhead();
        if packet.len() < need {
            return Err(SrtpError::NoRoom {
                need,
                got: packet.len(),
            });
        }

        let ssrc = read_u32(packet, 8);
        let sequence =
            u16::from_be_bytes([*packet.get(2).unwrap_or(&0), *packet.get(3).unwrap_or(&0)]);
        let index = self.rtp.next(sequence);
        let roc = self.rtp.rollover();

        if self.policy.encrypt_rtp {
            let (head, payload) = packet
                .get_mut(..len)
                .ok_or(SrtpError::Malformed)?
                .split_at_mut(header);
            self.keys
                .rtp(index)
                .encrypt_rtp(self.policy.suite, head, ssrc, index, roc, payload)?;
        }

        let mut at = len;
        if let Some(mki) = self.policy.mki {
            mki.write(packet.get_mut(at..).unwrap_or_default());
            at += mki.len();
        }
        if self.policy.authenticate_rtp {
            let tag = self.policy.suite.tag();
            let mut bytes = [0_u8; sha1::DIGEST];
            self.keys.rtp(index).tag(
                &[packet.get(..len).unwrap_or_default(), &roc.to_be_bytes()],
                tag,
                &mut bytes,
            );
            if let Some(slot) = packet.get_mut(at..at + tag) {
                slot.copy_from_slice(bytes.get(..tag).unwrap_or_default());
            }
            at += tag;
        }

        self.rtp_packets += 1;
        Ok(at)
    }

    /// Protect the RTCP compound packet occupying the first `len` octets.
    ///
    /// # Errors
    ///
    /// As `protect_rtp`, with §9.2's much lower SRTCP limit.
    pub fn protect_rtcp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        if self.rtcp_packets >= RTCP_LIMIT {
            return Err(SrtpError::KeyExhausted);
        }
        if len < RTCP_HEADER {
            return Err(SrtpError::TooShort { got: len });
        }
        let need = len + self.policy.rtcp_overhead();
        if packet.len() < need {
            return Err(SrtpError::NoRoom {
                need,
                got: packet.len(),
            });
        }

        let ssrc = read_u32(packet, 4);
        let index = self.rtcp_index;
        let word = if self.policy.encrypt_rtcp {
            index | RTCP_ENCRYPTED
        } else {
            index
        };

        if self.policy.encrypt_rtcp {
            let (head, payload) = packet
                .get_mut(..len)
                .ok_or(SrtpError::Malformed)?
                .split_at_mut(RTCP_HEADER);
            self.keys.rtcp(index).encrypt_rtcp(
                self.policy.suite,
                head,
                ssrc,
                index,
                word,
                payload,
            )?;
        }

        let mut at = len;
        if let Some(slot) = packet.get_mut(at..at + RTCP_INDEX) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        at += RTCP_INDEX;

        // the tag covers the packet and the index word but not the MKI, so it
        // is computed here, before the MKI moves `at` along
        let tag = self.policy.suite.rtcp_tag();
        let mut bytes = [0_u8; sha1::DIGEST];
        self.keys
            .rtcp(index)
            .tag(&[packet.get(..at).unwrap_or_default()], tag, &mut bytes);
        if let Some(mki) = self.policy.mki {
            mki.write(packet.get_mut(at..).unwrap_or_default());
            at += mki.len();
        }
        if let Some(slot) = packet.get_mut(at..at + tag) {
            slot.copy_from_slice(bytes.get(..tag).unwrap_or_default());
        }
        at += tag;

        // §3.4: "incremented by one, modulo 2^31, after each SRTCP packet is
        // sent", and never reset, which is why the counter is separate from
        // the limit above
        self.rtcp_index = (self.rtcp_index + 1) % (1 << 31);
        self.rtcp_packets += 1;
        Ok(at)
    }
}

/// One remote stream's index and replay state, bound to an SSRC.
#[derive(Debug, Clone, Copy)]
struct Stream {
    ssrc: u32,
    index: Receiving,
    replay: Replay,
}

/// The receiving half of an SRTP session.
pub struct Unprotector {
    policy: Policy,
    keys: Derived,
    rtp: Option<Stream>,
    rtcp: Option<(u32, Replay)>,
    initial: u32,
}

impl Unprotector {
    /// An unprotector for one incoming stream.
    #[must_use]
    pub fn new(policy: Policy, master: Master) -> Self {
        Self {
            keys: Derived::new(&policy, master),
            policy,
            rtp: None,
            rtcp: None,
            initial: 0,
        }
    }

    /// Start from a rollover counter given out of band, for a receiver
    /// joining a session already in progress (§3.3.1).
    #[must_use]
    pub fn joining(policy: Policy, master: Master, rollover: u32) -> Self {
        Self {
            initial: rollover,
            ..Self::new(policy, master)
        }
    }

    /// The rollover counter of the stream being received, which is what a
    /// second receiver of the same stream would have to be given (§3.3.1).
    #[must_use]
    pub fn rollover(&self) -> u32 {
        self.rtp
            .map_or(self.initial, |stream| stream.index.rollover())
    }

    /// The state a packet from `ssrc` is judged against.
    ///
    /// A packet whose SSRC is not the one we are latched to gets a fresh
    /// stream — a copy, not the stored one. Nothing is written back until the
    /// tag verifies, so a forged packet carrying an unused SSRC cannot clear
    /// the replay window of the stream that is actually running.
    fn stream_for(&self, ssrc: u32) -> Stream {
        match self.rtp {
            Some(stream) if stream.ssrc == ssrc => stream,
            Some(_) => Stream {
                ssrc,
                index: Receiving::default(),
                replay: Replay::default(),
            },
            None => Stream {
                ssrc,
                index: Receiving::joining(self.initial),
                replay: Replay::default(),
            },
        }
    }

    /// Verify and decrypt an SRTP packet in place, returning the length of
    /// the RTP packet inside it.
    ///
    /// The order is §3.3's: check the replay list, then the tag, then
    /// decrypt, and only then move the counters. A packet that fails leaves
    /// no state behind, which is what stops a forged index from punching a
    /// hole in the replay window.
    ///
    /// # Errors
    ///
    /// A short or malformed packet, a replay, or a tag that does not match.
    pub fn unprotect_rtp(&mut self, packet: &mut [u8]) -> Result<usize, SrtpError> {
        let tag = if self.policy.authenticate_rtp {
            self.policy.suite.tag()
        } else {
            0
        };
        let trailer = tag + self.policy.mki_len();
        let body = packet
            .len()
            .checked_sub(trailer)
            .ok_or(SrtpError::TooShort { got: packet.len() })?;
        let header = rtp_header_len(packet.get(..body).ok_or(SrtpError::Malformed)?)?;

        let ssrc = read_u32(packet, 8);
        let sequence =
            u16::from_be_bytes([*packet.get(2).unwrap_or(&0), *packet.get(3).unwrap_or(&0)]);

        let mut stream = self.stream_for(ssrc);
        let estimate: Estimate = stream.index.estimate(sequence);
        if !stream.replay.accepts(estimate.index) {
            return Err(SrtpError::Replayed);
        }

        self.check_mki(packet, body)?;
        if tag > 0 {
            let mut expected = [0_u8; sha1::DIGEST];
            self.keys.rtp(estimate.index).tag(
                &[
                    packet.get(..body).unwrap_or_default(),
                    &estimate.rollover().to_be_bytes(),
                ],
                tag,
                &mut expected,
            );
            let found = packet
                .get(body + self.policy.mki_len()..)
                .unwrap_or_default();
            if !equal(expected.get(..tag).unwrap_or_default(), found) {
                return Err(SrtpError::NotAuthentic);
            }
        }

        if self.policy.encrypt_rtp {
            let (head, payload) = packet
                .get_mut(..body)
                .ok_or(SrtpError::Malformed)?
                .split_at_mut(header);
            self.keys.rtp(estimate.index).encrypt_rtp(
                self.policy.suite,
                head,
                ssrc,
                estimate.index,
                estimate.rollover(),
                payload,
            )?;
        }

        stream.index.accept(estimate);
        stream.replay.record(estimate.index);
        self.rtp = Some(stream);
        Ok(body)
    }

    /// Verify and decrypt an SRTCP packet in place, returning the length of
    /// the RTCP compound packet inside it.
    ///
    /// # Errors
    ///
    /// As `unprotect_rtp`.
    pub fn unprotect_rtcp(&mut self, packet: &mut [u8]) -> Result<usize, SrtpError> {
        let tag = self.policy.suite.rtcp_tag();
        let trailer = tag + self.policy.mki_len();
        let with_index = packet
            .len()
            .checked_sub(trailer)
            .ok_or(SrtpError::TooShort { got: packet.len() })?;
        let body = with_index
            .checked_sub(RTCP_INDEX)
            .filter(|body| *body >= RTCP_HEADER)
            .ok_or(SrtpError::TooShort { got: packet.len() })?;

        let word = read_u32(packet, body);
        let index = word & !RTCP_ENCRYPTED;
        let ssrc = read_u32(packet, 4);

        // a copy, for the same reason as on the RTP side: the stored window
        // moves only once the tag has verified
        let mut replay = match self.rtcp {
            Some((known, replay)) if known == ssrc => replay,
            _ => Replay::default(),
        };
        if !replay.accepts(u64::from(index)) {
            return Err(SrtpError::Replayed);
        }

        self.check_mki(packet, with_index)?;
        let mut expected = [0_u8; sha1::DIGEST];
        self.keys.rtcp(index).tag(
            &[packet.get(..with_index).unwrap_or_default()],
            tag,
            &mut expected,
        );
        let found = packet
            .get(with_index + self.policy.mki_len()..)
            .unwrap_or_default();
        if !equal(expected.get(..tag).unwrap_or_default(), found) {
            return Err(SrtpError::NotAuthentic);
        }

        if word & RTCP_ENCRYPTED != 0 {
            let (head, payload) = packet
                .get_mut(..body)
                .ok_or(SrtpError::Malformed)?
                .split_at_mut(RTCP_HEADER);
            self.keys.rtcp(index).encrypt_rtcp(
                self.policy.suite,
                head,
                ssrc,
                index,
                word,
                payload,
            )?;
        }

        replay.record(u64::from(index));
        self.rtcp = Some((ssrc, replay));
        Ok(body)
    }

    fn check_mki(&self, packet: &[u8], at: usize) -> Result<(), SrtpError> {
        let Some(mki) = self.policy.mki else {
            return Ok(());
        };
        let found = packet
            .get(at..at + mki.len())
            .ok_or(SrtpError::TooShort { got: packet.len() })?;
        if mki.matches(found) {
            Ok(())
        } else {
            Err(SrtpError::UnknownKey)
        }
    }
}

/// Where the RTP payload begins: the fixed header, the CSRC list, and the
/// header extension if the X bit says there is one (RFC 3550 §5.1, §5.3.1).
fn rtp_header_len(packet: &[u8]) -> Result<usize, SrtpError> {
    let first = *packet.first().ok_or(SrtpError::TooShort { got: 0 })?;
    if first >> 6 != 2 {
        return Err(SrtpError::Malformed);
    }
    let mut len = RTP_HEADER + usize::from(first & 0x0f) * 4;
    if first & 0x10 != 0 {
        let words = u16::from_be_bytes([
            *packet.get(len + 2).ok_or(SrtpError::Malformed)?,
            *packet.get(len + 3).ok_or(SrtpError::Malformed)?,
        ]);
        len += 4 + usize::from(words) * 4;
    }
    if len > packet.len() {
        return Err(SrtpError::Malformed);
    }
    Ok(len)
}

fn read_u32(packet: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([
        *packet.get(at).unwrap_or(&0),
        *packet.get(at + 1).unwrap_or(&0),
        *packet.get(at + 2).unwrap_or(&0),
        *packet.get(at + 3).unwrap_or(&0),
    ])
}

/// Comparison that takes the same time whether the tags differ in the first
/// octet or the last. The lengths are public, so only the contents have to be
/// hidden, and `black_box` is what stops the loop being turned back into an
/// early return.
fn equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    core::hint::black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use super::{Master, Mki, Policy, Protector, Rate, SrtpError, Suite, Unprotector};

    const SSRC: u32 = 0xdead_beef;

    fn master() -> Master {
        Master::new([0x11; 16], [0x22; 14])
    }

    fn other_master() -> Master {
        Master::new([0x33; 16], [0x22; 14])
    }

    fn pair(policy: Policy) -> (Protector, Unprotector) {
        (
            Protector::new(policy, master()),
            Unprotector::new(policy, master()),
        )
    }

    /// A minimal RTP packet: version 2, payload type 8, the given sequence
    /// number and a payload that is easy to recognise.
    fn packet(sequence: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x80, 0x08];
        bytes.extend_from_slice(&sequence.to_be_bytes());
        bytes.extend_from_slice(&0x0001_0000_u32.to_be_bytes());
        bytes.extend_from_slice(&SSRC.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    /// A receiver report followed by an SDES, which is the shape RFC 3550
    /// §6.1 requires of a compound packet. The content does not matter here,
    /// only that the first eight octets are a header.
    fn compound() -> Vec<u8> {
        let mut bytes = vec![0x81, 201, 0x00, 0x07];
        bytes.extend_from_slice(&SSRC.to_be_bytes());
        bytes.extend_from_slice(&[0x99; 24]);
        bytes
    }

    fn room(packet: &[u8], overhead: usize) -> Vec<u8> {
        let mut buffer = packet.to_vec();
        buffer.resize(packet.len() + overhead, 0);
        buffer
    }

    #[test]
    fn a_packet_survives_the_round_trip_under_every_suite() {
        for suite in [Suite::AesCm80, Suite::AesCm32, Suite::AesF8] {
            let policy = Policy::new(suite);
            let (mut protector, mut unprotector) = pair(policy);
            let plain = packet(1000, b"nine bytes");

            let mut buffer = room(&plain, protector.rtp_overhead());
            let len = protector
                .protect_rtp(&mut buffer, plain.len())
                .expect("protects");
            assert_eq!(len, plain.len() + suite.tag(), "{suite:?}");
            assert_ne!(
                buffer.get(12..plain.len()),
                plain.get(12..),
                "{suite:?} left the payload readable"
            );
            assert_eq!(
                buffer.get(..12),
                plain.get(..12),
                "{suite:?} touched the header"
            );

            let mut received = buffer.get(..len).unwrap_or_default().to_vec();
            let back = unprotector
                .unprotect_rtp(&mut received)
                .expect("authenticates");
            assert_eq!(received.get(..back), plain.get(..), "{suite:?}");
        }
    }

    #[test]
    fn a_changed_payload_is_refused() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let plain = packet(1, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");

        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        if let Some(byte) = received.get_mut(14) {
            *byte ^= 0x01;
        }
        assert_eq!(
            unprotector.unprotect_rtp(&mut received),
            Err(SrtpError::NotAuthentic)
        );
    }

    #[test]
    fn a_changed_header_is_refused() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let plain = packet(1, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");

        // the timestamp, which is in the clear and would otherwise be free to
        // rewrite in flight
        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        if let Some(byte) = received.get_mut(6) {
            *byte ^= 0x40;
        }
        assert_eq!(
            unprotector.unprotect_rtp(&mut received),
            Err(SrtpError::NotAuthentic)
        );
    }

    #[test]
    fn a_changed_tag_is_refused() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let plain = packet(1, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");

        for at in plain.len()..len {
            let mut received = buffer.get(..len).unwrap_or_default().to_vec();
            if let Some(byte) = received.get_mut(at) {
                *byte ^= 0x80;
            }
            assert_eq!(
                unprotector.unprotect_rtp(&mut received),
                Err(SrtpError::NotAuthentic),
                "octet {at} of the tag"
            );
        }
    }

    #[test]
    fn another_key_does_not_open_it() {
        let policy = Policy::new(Suite::AesCm80);
        let mut protector = Protector::new(policy, master());
        let mut stranger = Unprotector::new(policy, other_master());
        let plain = packet(1, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");

        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        assert_eq!(
            stranger.unprotect_rtp(&mut received),
            Err(SrtpError::NotAuthentic)
        );
    }

    #[test]
    fn the_same_packet_twice_is_a_replay() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let plain = packet(7, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
        let wire = buffer.get(..len).unwrap_or_default().to_vec();

        let mut first = wire.clone();
        assert!(unprotector.unprotect_rtp(&mut first).is_ok());
        let mut again = wire;
        assert_eq!(
            unprotector.unprotect_rtp(&mut again),
            Err(SrtpError::Replayed)
        );
    }

    // §3.3 step 5 puts the replay check before the tag check but the replay
    // list update after it. A packet that fails to authenticate must leave
    // the window exactly as it was, or an attacker can make the receiver
    // discard the real packet that follows
    #[test]
    fn a_forgery_does_not_consume_an_index() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let plain = packet(42, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
        let wire = buffer.get(..len).unwrap_or_default().to_vec();

        let mut forged = wire.clone();
        if let Some(byte) = forged.last_mut() {
            *byte ^= 0xff;
        }
        assert_eq!(
            unprotector.unprotect_rtp(&mut forged),
            Err(SrtpError::NotAuthentic)
        );

        let mut genuine = wire;
        assert!(
            unprotector.unprotect_rtp(&mut genuine).is_ok(),
            "the real packet still has its place in the window"
        );
    }

    // the same argument one level up: a packet carrying an SSRC we are not
    // latched to must not be able to reset the stream that is running
    #[test]
    fn a_stranger_ssrc_cannot_clear_the_window() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let mut wire = Vec::new();
        for sequence in 100..105 {
            let plain = packet(sequence, b"payload");
            let mut buffer = room(&plain, protector.rtp_overhead());
            let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
            wire.push(buffer.get(..len).unwrap_or_default().to_vec());
        }
        for packet in &wire {
            let mut received = packet.clone();
            assert!(unprotector.unprotect_rtp(&mut received).is_ok());
        }

        let mut intruder = wire.first().cloned().unwrap_or_default();
        if let Some(slot) = intruder.get_mut(8..12) {
            slot.copy_from_slice(&0x1234_5678_u32.to_be_bytes());
        }
        assert_eq!(
            unprotector.unprotect_rtp(&mut intruder),
            Err(SrtpError::NotAuthentic)
        );

        for packet in &wire {
            let mut received = packet.clone();
            assert_eq!(
                unprotector.unprotect_rtp(&mut received),
                Err(SrtpError::Replayed),
                "the window survived the intruder"
            );
        }
    }

    #[test]
    fn a_stream_running_past_a_wrap_stays_readable() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let mut sequence = 65_500_u16;
        for step in 0..600_u32 {
            let payload = step.to_be_bytes();
            let plain = packet(sequence, &payload);
            let mut buffer = room(&plain, protector.rtp_overhead());
            let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
            let mut received = buffer.get(..len).unwrap_or_default().to_vec();
            let back = unprotector
                .unprotect_rtp(&mut received)
                .unwrap_or_else(|error| panic!("sequence {sequence}: {error}"));
            assert_eq!(received.get(..back), plain.get(..));
            sequence = sequence.wrapping_add(1);
        }
        assert_eq!(protector.rollover(), 1);
        assert_eq!(unprotector.rollover(), 1);
    }

    #[test]
    fn reordering_inside_the_window_is_accepted_once_each() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let mut wire = Vec::new();
        for sequence in 0..8 {
            let plain = packet(sequence, b"payload");
            let mut buffer = room(&plain, protector.rtp_overhead());
            let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
            wire.push(buffer.get(..len).unwrap_or_default().to_vec());
        }
        for order in [7, 3, 5, 0, 6, 1, 4, 2] {
            let mut received = wire.get(order).cloned().unwrap_or_default();
            assert!(
                unprotector.unprotect_rtp(&mut received).is_ok(),
                "packet {order} out of order"
            );
        }
        for order in 0..8 {
            let mut received = wire.get(order).cloned().unwrap_or_default();
            assert_eq!(
                unprotector.unprotect_rtp(&mut received),
                Err(SrtpError::Replayed)
            );
        }
    }

    #[test]
    fn a_csrc_list_and_an_extension_are_authenticated_but_left_readable() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        // two CSRCs and a one-word header extension
        let mut plain = vec![0x92, 0x08, 0x00, 0x05];
        plain.extend_from_slice(&0x0000_00a0_u32.to_be_bytes());
        plain.extend_from_slice(&SSRC.to_be_bytes());
        plain.extend_from_slice(&[0xaa; 8]);
        plain.extend_from_slice(&[0xbe, 0xde, 0x00, 0x01]);
        plain.extend_from_slice(&[0xcc; 4]);
        let header = plain.len();
        plain.extend_from_slice(b"payload");

        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
        assert_eq!(
            buffer.get(..header),
            plain.get(..header),
            "everything up to the payload stays as it was"
        );
        assert_ne!(buffer.get(header..plain.len()), plain.get(header..));

        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        let back = unprotector.unprotect_rtp(&mut received).expect("ok");
        assert_eq!(received.get(..back), plain.get(..));
    }

    #[test]
    fn unencrypted_srtp_still_authenticates() {
        let mut policy = Policy::new(Suite::AesCm80);
        policy.encrypt_rtp = false;
        let (mut protector, mut unprotector) = pair(policy);
        let plain = packet(1, b"in the clear");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
        assert_eq!(buffer.get(..plain.len()), plain.get(..));
        assert_eq!(len, plain.len() + 10);

        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        assert_eq!(unprotector.unprotect_rtp(&mut received), Ok(plain.len()));

        // a second packet, so the replay check — which §3.3 runs first — is
        // not what refuses it
        let next = packet(2, b"in the clear");
        let mut buffer = room(&next, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, next.len()).expect("ok");
        let mut tampered = buffer.get(..len).unwrap_or_default().to_vec();
        if let Some(byte) = tampered.get_mut(13) {
            *byte ^= 1;
        }
        assert_eq!(
            unprotector.unprotect_rtp(&mut tampered),
            Err(SrtpError::NotAuthentic)
        );
    }

    #[test]
    fn unauthenticated_srtp_carries_no_tag() {
        let mut policy = Policy::new(Suite::AesCm80);
        policy.authenticate_rtp = false;
        let (mut protector, mut unprotector) = pair(policy);
        assert_eq!(protector.rtp_overhead(), 0);

        let plain = packet(1, b"payload");
        let mut buffer = plain.clone();
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
        assert_eq!(len, plain.len());

        let mut received = buffer;
        assert_eq!(unprotector.unprotect_rtp(&mut received), Ok(plain.len()));
        assert_eq!(received.get(..), plain.get(..));
    }

    #[test]
    fn a_buffer_with_no_room_for_the_tag_is_refused_rather_than_truncated() {
        let (mut protector, _) = pair(Policy::new(Suite::AesCm80));
        let plain = packet(1, b"payload");
        let mut buffer = plain.clone();
        assert_eq!(
            protector.protect_rtp(&mut buffer, plain.len()),
            Err(SrtpError::NoRoom {
                need: plain.len() + 10,
                got: plain.len(),
            })
        );
        assert_eq!(buffer, plain, "and nothing was written");
    }

    #[test]
    fn a_packet_that_is_not_rtp_is_refused() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let mut buffer = vec![0x40; 32];
        assert_eq!(
            protector.protect_rtp(&mut buffer, 20),
            Err(SrtpError::Malformed)
        );
        let mut short = vec![0x80, 0x08, 0x00];
        assert_eq!(
            unprotector.unprotect_rtp(&mut short),
            Err(SrtpError::TooShort { got: 3 })
        );
    }

    #[test]
    fn an_extension_longer_than_the_packet_is_refused() {
        let (mut protector, _) = pair(Policy::new(Suite::AesCm80));
        let mut plain = vec![0x90, 0x08, 0x00, 0x01];
        plain.extend_from_slice(&[0; 8]);
        plain.extend_from_slice(&[0xbe, 0xde, 0xff, 0xff]);
        let len = plain.len();
        let mut buffer = room(&plain, 16);
        assert_eq!(
            protector.protect_rtp(&mut buffer, len),
            Err(SrtpError::Malformed)
        );
    }

    #[test]
    fn an_rtcp_packet_survives_the_round_trip() {
        for suite in [Suite::AesCm80, Suite::AesCm32, Suite::AesF8] {
            let policy = Policy::new(suite);
            let (mut protector, mut unprotector) = pair(policy);
            let plain = compound();

            let mut buffer = room(&plain, protector.rtcp_overhead());
            let len = protector
                .protect_rtcp(&mut buffer, plain.len())
                .expect("protects");
            // four octets of index and ten of tag, whatever the suite says
            // about SRTP tags: §5.2 forbids shortening SRTCP's
            assert_eq!(len, plain.len() + 14, "{suite:?}");
            assert_eq!(buffer.get(..8), plain.get(..8), "{suite:?}");
            assert_ne!(buffer.get(8..plain.len()), plain.get(8..), "{suite:?}");

            let mut received = buffer.get(..len).unwrap_or_default().to_vec();
            let back = unprotector
                .unprotect_rtcp(&mut received)
                .expect("authenticates");
            assert_eq!(received.get(..back), plain.get(..), "{suite:?}");
        }
    }

    #[test]
    fn the_rtcp_index_is_in_the_clear_and_advances() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        for expected in 0..4_u32 {
            let plain = compound();
            let mut buffer = room(&plain, protector.rtcp_overhead());
            let len = protector
                .protect_rtcp(&mut buffer, plain.len())
                .expect("ok");
            let word = u32::from_be_bytes([
                *buffer.get(plain.len()).unwrap_or(&0),
                *buffer.get(plain.len() + 1).unwrap_or(&0),
                *buffer.get(plain.len() + 2).unwrap_or(&0),
                *buffer.get(plain.len() + 3).unwrap_or(&0),
            ]);
            assert_eq!(word & 0x8000_0000, 0x8000_0000, "the E flag says encrypted");
            assert_eq!(word & 0x7fff_ffff, expected);

            let mut received = buffer.get(..len).unwrap_or_default().to_vec();
            assert!(unprotector.unprotect_rtcp(&mut received).is_ok());
        }
    }

    #[test]
    fn an_unencrypted_rtcp_packet_says_so_in_its_flag() {
        let mut policy = Policy::new(Suite::AesCm80);
        policy.encrypt_rtcp = false;
        let (mut protector, mut unprotector) = pair(policy);
        let plain = compound();
        let mut buffer = room(&plain, protector.rtcp_overhead());
        let len = protector
            .protect_rtcp(&mut buffer, plain.len())
            .expect("ok");
        assert_eq!(buffer.get(..plain.len()), plain.get(..));
        assert_eq!(buffer.get(plain.len()), Some(&0));

        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        assert_eq!(unprotector.unprotect_rtcp(&mut received), Ok(plain.len()));
    }

    #[test]
    fn a_replayed_rtcp_packet_is_refused() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let plain = compound();
        let mut buffer = room(&plain, protector.rtcp_overhead());
        let len = protector
            .protect_rtcp(&mut buffer, plain.len())
            .expect("ok");
        let wire = buffer.get(..len).unwrap_or_default().to_vec();

        let mut first = wire.clone();
        assert!(unprotector.unprotect_rtcp(&mut first).is_ok());
        let mut again = wire;
        assert_eq!(
            unprotector.unprotect_rtcp(&mut again),
            Err(SrtpError::Replayed)
        );
    }

    #[test]
    fn a_changed_rtcp_index_is_refused() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let plain = compound();
        let mut buffer = room(&plain, protector.rtcp_overhead());
        let len = protector
            .protect_rtcp(&mut buffer, plain.len())
            .expect("ok");
        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        if let Some(byte) = received.get_mut(plain.len() + 3) {
            *byte ^= 0x10;
        }
        assert_eq!(
            unprotector.unprotect_rtcp(&mut received),
            Err(SrtpError::NotAuthentic)
        );
    }

    #[test]
    fn the_master_key_identifier_travels_and_is_checked() {
        let mut policy = Policy::new(Suite::AesCm80);
        policy.mki = Mki::new(0x0102_0304, 4);
        let (mut protector, mut unprotector) = pair(policy);
        assert_eq!(protector.rtp_overhead(), 14);

        let plain = packet(1, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
        assert_eq!(
            buffer.get(plain.len()..plain.len() + 4),
            Some(&[0x01, 0x02, 0x03, 0x04][..])
        );

        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        assert_eq!(unprotector.unprotect_rtp(&mut received), Ok(plain.len()));

        let next = packet(2, b"payload");
        let mut buffer = room(&next, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, next.len()).expect("ok");
        let mut stranger = buffer.get(..len).unwrap_or_default().to_vec();
        if let Some(byte) = stranger.get_mut(next.len()) {
            *byte = 0xff;
        }
        assert_eq!(
            unprotector.unprotect_rtp(&mut stranger),
            Err(SrtpError::UnknownKey)
        );
    }

    #[test]
    fn an_identifier_wider_than_its_value_is_refused() {
        assert!(Mki::new(1, 0).is_none());
        assert!(Mki::new(1, 1).is_some());
        assert!(Mki::new(1, 16).is_some());
        assert!(Mki::new(1, 17).is_none());
    }

    #[test]
    fn a_key_derivation_rate_survives_the_round_trip() {
        let mut policy = Policy::new(Suite::AesCm80);
        policy.rate = Rate::from_exponent(2).expect("in range");
        let (mut protector, mut unprotector) = pair(policy);
        for sequence in 0..12 {
            let plain = packet(sequence, b"payload");
            let mut buffer = room(&plain, protector.rtp_overhead());
            let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
            let mut received = buffer.get(..len).unwrap_or_default().to_vec();
            let back = unprotector
                .unprotect_rtp(&mut received)
                .unwrap_or_else(|error| panic!("sequence {sequence}: {error}"));
            assert_eq!(received.get(..back), plain.get(..));
        }
    }

    #[test]
    fn the_suite_names_are_the_ones_sdp_carries() {
        assert_eq!(Suite::AesCm80.name(), "AES_CM_128_HMAC_SHA1_80");
        assert_eq!(Suite::AesCm32.name(), "AES_CM_128_HMAC_SHA1_32");
        assert_eq!(Suite::AesF8.name(), "F8_128_HMAC_SHA1_80");
        for suite in [Suite::AesCm80, Suite::AesCm32, Suite::AesF8] {
            assert_eq!(Suite::from_name(suite.name()), Some(suite));
        }
        assert_eq!(
            Suite::from_name("aes_cm_128_hmac_sha1_80"),
            Some(Suite::AesCm80)
        );
        assert_eq!(Suite::from_name("AES_CM_256_HMAC_SHA1_80"), None);
    }

    // §4.1.1 puts the SSRC in the IV so that one master key can protect more
    // than one stream. Without it two streams at the same index produce the
    // same keystream, which is the two-time pad §9.1 calls catastrophic
    #[test]
    fn two_streams_under_one_key_do_not_share_a_keystream() {
        let policy = Policy::new(Suite::AesCm80);
        let mut first = Protector::new(policy, master());
        let mut second = Protector::new(policy, master());

        let mut one = packet(500, b"the same payload");
        let mut two = one.clone();
        if let Some(slot) = two.get_mut(8..12) {
            slot.copy_from_slice(&0x0bad_cafe_u32.to_be_bytes());
        }

        let plain = one.len();
        one.resize(plain + first.rtp_overhead(), 0);
        two.resize(plain + second.rtp_overhead(), 0);
        first.protect_rtp(&mut one, plain).expect("ok");
        second.protect_rtp(&mut two, plain).expect("ok");

        assert_ne!(one.get(12..plain), two.get(12..plain));
    }

    // §4.2: the tag covers the packet concatenated with the ROC. Two packets
    // that are identical on the wire but sit either side of a wrap differ
    // only in that counter, so their tags have to differ — with encryption
    // off, nothing else can be making them differ
    #[test]
    fn the_rollover_counter_reaches_the_tag() {
        let mut policy = Policy::new(Suite::AesCm80);
        policy.encrypt_rtp = false;
        let (mut protector, _) = pair(policy);

        let tag_of = |protector: &mut Protector, sequence: u16| {
            let plain = packet(sequence, b"payload");
            let mut buffer = room(&plain, protector.rtp_overhead());
            let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
            buffer.get(plain.len()..len).unwrap_or_default().to_vec()
        };

        let before = tag_of(&mut protector, 100);
        tag_of(&mut protector, 65_535);
        tag_of(&mut protector, 0);
        assert_eq!(protector.rollover(), 1);
        let after = tag_of(&mut protector, 100);

        assert_ne!(before, after);
    }

    // §4.1.2.2 puts the ROC in the f8 IV, where the packet index is not.
    // Without it the two sides of a wrap would share a keystream
    #[test]
    fn the_rollover_counter_reaches_the_f8_keystream() {
        let (mut protector, _) = pair(Policy::new(Suite::AesF8));

        let body_of = |protector: &mut Protector, sequence: u16| {
            let plain = packet(sequence, b"payload");
            let mut buffer = room(&plain, protector.rtp_overhead());
            protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
            buffer.get(12..plain.len()).unwrap_or_default().to_vec()
        };

        let before = body_of(&mut protector, 100);
        body_of(&mut protector, 65_535);
        body_of(&mut protector, 0);
        let after = body_of(&mut protector, 100);

        assert_ne!(before, after);
    }

    // the two directions use different master keys, so a packet we sent must
    // not verify against our own receiving context — the check that catches
    // an implementation that quietly uses one context for both
    #[test]
    fn our_own_packet_does_not_come_back_in() {
        let policy = Policy::new(Suite::AesCm80);
        let mut protector = Protector::new(policy, master());
        let mut unprotector = Unprotector::new(policy, other_master());
        let plain = packet(1, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector.protect_rtp(&mut buffer, plain.len()).expect("ok");
        let mut received = buffer.get(..len).unwrap_or_default().to_vec();
        assert_eq!(
            unprotector.unprotect_rtp(&mut received),
            Err(SrtpError::NotAuthentic)
        );
    }
}
