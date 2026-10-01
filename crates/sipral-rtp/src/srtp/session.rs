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

use super::aead::{self, Gcm, TagMismatch};
use super::cipher::{self, Counter, Exhausted, F8};
use super::index::{Estimate, Receiving, Replay, Sending};
use super::kdf::{self, Lengths, Master, Rate, Session};
use super::sha1;
use zeroize::Zeroizing;

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

/// The transforms this stack implements: RFC 4568 §6.2's three, RFC 6188's
/// two wider `AES_CM` suites, and RFC 7714's two AEAD ones.
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
    /// `AES_256_CM_HMAC_SHA1_80` (RFC 6188): `AesCm80` with a 256-bit key.
    Aes256Cm80,
    /// `AES_256_CM_HMAC_SHA1_32` (RFC 6188): `AesCm32` with a 256-bit key.
    Aes256Cm32,
    /// `AEAD_AES_128_GCM` (RFC 7714): AES-GCM with a 128-bit key, tying
    /// confidentiality and integrity into one transform rather than pairing
    /// AES-CM with a separate HMAC.
    AeadAes128Gcm,
    /// `AEAD_AES_256_GCM` (RFC 7714): the same, with a 256-bit key.
    AeadAes256Gcm,
}

impl Suite {
    /// Every suite this stack implements, strongest first: the order the
    /// facade offers them in, and the order it picks among a DTLS-SRTP
    /// peer's own offer with (RFC 5764 §4.1.1 leaves that choice to the
    /// server, unlike RFC 4568's SDES, which is bound to the offerer's own
    /// order).
    pub(crate) const STRENGTH: [Self; 7] = [
        Self::AeadAes256Gcm,
        Self::AeadAes128Gcm,
        Self::Aes256Cm80,
        Self::AesCm80,
        Self::AesF8,
        Self::Aes256Cm32,
        Self::AesCm32,
    ];

    /// Whether this suite ties confidentiality and integrity into one AEAD
    /// transform rather than pairing a cipher with a separate HMAC.
    #[must_use]
    pub const fn is_aead(self) -> bool {
        matches!(self, Self::AeadAes128Gcm | Self::AeadAes256Gcm)
    }

    /// The master and session encryption key length, `n_e`.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesCm80 | Self::AesCm32 | Self::AesF8 | Self::AeadAes128Gcm => cipher::KEY_128,
            Self::Aes256Cm80 | Self::Aes256Cm32 | Self::AeadAes256Gcm => cipher::KEY_256,
        }
    }

    /// The master and session salt length, `n_s`: RFC 7714 §8.1's twelve
    /// octets for the AEAD suites, RFC 3711 §5.1's fourteen for the rest.
    #[must_use]
    pub const fn salt_len(self) -> usize {
        if self.is_aead() {
            aead::SALT
        } else {
            kdf::SALT
        }
    }

    pub(crate) const fn lengths(self) -> Lengths {
        Lengths {
            key: self.key_len(),
            salt: self.salt_len(),
            auth: !self.is_aead(),
        }
    }

    /// The authentication tag length on SRTP packets, `n_tag`: the AEAD tag
    /// RFC 7714 §10 fixes at sixteen octets, embedded in the ciphertext
    /// rather than appended after it, for the two GCM suites.
    #[must_use]
    pub const fn tag(self) -> usize {
        match self {
            Self::AesCm80 | Self::AesF8 | Self::Aes256Cm80 => 10,
            Self::AesCm32 | Self::Aes256Cm32 => 4,
            Self::AeadAes128Gcm | Self::AeadAes256Gcm => aead::TAG,
        }
    }

    /// The tag length on SRTCP packets.
    ///
    /// §5.2: "for SRTCP, the pre-defined HMAC-SHA1 MUST NOT be applied with a
    /// value of n_tag, nor n_a, that are smaller than these defaults" — so
    /// the short suites shorten SRTP tags and leave SRTCP's alone. The AEAD
    /// suites use the same sixteen-octet tag on both.
    #[must_use]
    pub const fn rtcp_tag(self) -> usize {
        if self.is_aead() { aead::TAG } else { 10 }
    }

    /// The name this suite carries in an `a=crypto` line (RFC 4568 §6.2, RFC
    /// 6188 §4, RFC 7714 §14.1).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AesCm80 => "AES_CM_128_HMAC_SHA1_80",
            Self::AesCm32 => "AES_CM_128_HMAC_SHA1_32",
            Self::AesF8 => "F8_128_HMAC_SHA1_80",
            Self::Aes256Cm80 => "AES_256_CM_HMAC_SHA1_80",
            Self::Aes256Cm32 => "AES_256_CM_HMAC_SHA1_32",
            Self::AeadAes128Gcm => "AEAD_AES_128_GCM",
            Self::AeadAes256Gcm => "AEAD_AES_256_GCM",
        }
    }

    /// The suite an `a=crypto` line names, if it is one we implement.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::STRENGTH
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
    /// silently truncated, and so is a value too wide for `length` octets to
    /// carry, which would go out truncated and never match coming back.
    #[must_use]
    pub fn new(value: u128, length: usize) -> Option<Self> {
        // the width is checked first, so the shift below is never by 128 bits
        // or more
        let fits = (1..=16).contains(&length) && (length == 16 || value >> (8 * length) == 0);
        fits.then_some(Self { value, length })
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
    /// The lifetime the key's owner declared for it (RFC 4568 §6.1): "the
    /// number of SRTP packets and the number of SRTCP packets each have to
    /// be less than the lifetime". `None` leaves §9.2's own limits, which
    /// hold either way.
    pub lifetime: Option<u64>,
}

impl Policy {
    /// The defaults of RFC 4568: encrypt and authenticate everything, derive
    /// the session keys once, no master key identifier, no lifetime but
    /// RFC 3711's.
    #[must_use]
    pub const fn new(suite: Suite) -> Self {
        Self {
            suite,
            rate: Rate::ONCE,
            encrypt_rtp: true,
            encrypt_rtcp: true,
            authenticate_rtp: true,
            mki: None,
            lifetime: None,
        }
    }

    /// How many packets of one kind this key may protect, or open, at most:
    /// §9.2's `limit`, or fewer than the declared lifetime.
    const fn allowance(&self, limit: u64) -> u64 {
        match self.lifetime {
            Some(lifetime) if lifetime.saturating_sub(1) < limit => lifetime.saturating_sub(1),
            _ => limit,
        }
    }

    pub(crate) const fn rtp_overhead(&self) -> usize {
        // RFC 7714 §8.2: an AEAD suite is always both encrypted and
        // authenticated, in the one transform, so its tag counts here
        // whatever `authenticate_rtp` says -- the flag has nothing to turn
        // off for these two suites
        let tag = if self.authenticate_rtp || self.suite.is_aead() {
            self.suite.tag()
        } else {
            0
        };
        tag + self.mki_len()
    }

    pub(crate) const fn rtcp_overhead(&self) -> usize {
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
    /// The sequence number does not move the packet index forward: it
    /// repeats the last one sent, or is behind it. Sent, it would be
    /// encrypted under a keystream already spent (§9.1) or read by the
    /// receiver as a rollover it never saw. A new master key starts a new
    /// index.
    IndexNotAdvancing,
    /// The master key or salt is not the width the suite calls for, so no
    /// session key is derived from it at all.
    KeyLength,
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
            Self::IndexNotAdvancing => {
                f.write_str("the sequence number does not move the packet index forward")
            }
            Self::KeyLength => {
                f.write_str("the master key or salt is not the width the suite calls for")
            }
        }
    }
}

impl core::error::Error for SrtpError {}

impl From<Exhausted> for SrtpError {
    fn from(_: Exhausted) -> Self {
        Self::TooLong
    }
}

/// The keystream generator for one direction and one protocol, when the
/// suite pairs a cipher with a separate authentication tag rather than
/// tying the two together in one AEAD transform.
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
            Suite::AesCm80 | Suite::AesCm32 | Suite::Aes256Cm80 | Suite::Aes256Cm32 => {
                Self::Counter(Counter::new(&keys.encryption))
            }
            Suite::AesF8 => Self::F8(F8::new(&keys.encryption, &keys.salt)),
            Suite::AeadAes128Gcm | Suite::AeadAes256Gcm => {
                unreachable!("an AEAD suite never builds a Keystream; see Engine::new")
            }
        }
    }

    fn apply(&self, iv: &[u8; cipher::BLOCK], data: &mut [u8]) -> Result<(), Exhausted> {
        match self {
            Self::Counter(counter) => counter.apply(iv, data),
            Self::F8(f8) => f8.apply(iv, data),
        }
    }
}

/// The two families of transform a suite can name: a keystream paired with a
/// separately computed HMAC tag, or one AEAD transform that produces both at
/// once.
#[expect(
    clippy::large_enum_variant,
    reason = "one AES key schedule either way, and there is one of these per session, not per packet"
)]
enum Cipher {
    Mac {
        keystream: Keystream,
        authentication: Zeroizing<[u8; kdf::AUTH]>,
    },
    Aead(Gcm),
}

/// One derivation's worth of session state: the cipher, and the salt the IV
/// needs.
struct Engine {
    cipher: Cipher,
    salt: Zeroizing<Vec<u8>>,
}

impl Engine {
    fn new(suite: Suite, keys: &Session) -> Self {
        let cipher = if suite.is_aead() {
            Cipher::Aead(Gcm::new(&keys.encryption))
        } else {
            Cipher::Mac {
                keystream: Keystream::new(suite, keys),
                authentication: match keys.authentication.as_ref() {
                    Some(key) => key.clone(),
                    None => {
                        unreachable!(
                            "a MAC suite's key derivation always derives an authentication key"
                        )
                    }
                },
            }
        };
        Self {
            cipher,
            salt: keys.salt.clone(),
        }
    }

    /// §4.1.1: `IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (i * 2^16)`.
    fn counter_iv(&self, ssrc: u32, index: u64) -> [u8; cipher::BLOCK] {
        let mut iv = [0_u8; cipher::BLOCK];
        if let Some(head) = iv.get_mut(..self.salt.len()) {
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

    /// RFC 7714 §8.1: `IV = (00 || SSRC || ROC || SEQ) XOR salt`, over the
    /// twelve-octet AEAD salt rather than AES-CM's fourteen.
    fn aead_rtp_iv(&self, ssrc: u32, roc: u32, seq: u16) -> [u8; aead::SALT] {
        let mut iv = [0_u8; aead::SALT];
        if let Some(slot) = iv.get_mut(2..6) {
            slot.copy_from_slice(&ssrc.to_be_bytes());
        }
        if let Some(slot) = iv.get_mut(6..10) {
            slot.copy_from_slice(&roc.to_be_bytes());
        }
        if let Some(slot) = iv.get_mut(10..12) {
            slot.copy_from_slice(&seq.to_be_bytes());
        }
        for (byte, salt) in iv.iter_mut().zip(self.salt.iter()) {
            *byte ^= salt;
        }
        iv
    }

    /// RFC 7714 §9.1: `IV = (00 || SSRC || 00 || 0+SRTCP index) XOR salt`.
    /// `index` is the plain 31-bit SRTCP index, without the E bit the wire
    /// format ORs into the same word — the IV always uses a "0" there,
    /// whichever way the packet went.
    fn aead_rtcp_iv(&self, ssrc: u32, index: u32) -> [u8; aead::SALT] {
        let mut iv = [0_u8; aead::SALT];
        if let Some(slot) = iv.get_mut(2..6) {
            slot.copy_from_slice(&ssrc.to_be_bytes());
        }
        if let Some(slot) = iv.get_mut(8..12) {
            slot.copy_from_slice(&(index & !RTCP_ENCRYPTED).to_be_bytes());
        }
        for (byte, salt) in iv.iter_mut().zip(self.salt.iter()) {
            *byte ^= salt;
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

    fn keystream(&self) -> &Keystream {
        match &self.cipher {
            Cipher::Mac { keystream, .. } => keystream,
            Cipher::Aead(_) => unreachable!("a MAC path is never taken for an AEAD suite"),
        }
    }

    fn gcm(&self) -> &Gcm {
        match &self.cipher {
            Cipher::Aead(gcm) => gcm,
            Cipher::Mac { .. } => unreachable!("an AEAD path is never taken for a MAC suite"),
        }
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
            Suite::AesF8 => Self::f8_rtp_iv(header, roc),
            _ => self.counter_iv(ssrc, index),
        };
        self.keystream().apply(&iv, payload)
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
            Suite::AesF8 => Self::f8_rtcp_iv(header, word),
            _ => self.counter_iv(ssrc, u64::from(index)),
        };
        self.keystream().apply(&iv, payload)
    }

    /// §4.2: `HMAC(k_a, M)` truncated to the left-most `tag` octets.
    fn tag(&self, parts: &[&[u8]], tag: usize, out: &mut [u8]) {
        let authentication = match &self.cipher {
            Cipher::Mac { authentication, .. } => authentication,
            Cipher::Aead(_) => unreachable!("an AEAD suite is never authenticated this way"),
        };
        let full = sha1::hmac(authentication.as_slice(), parts);
        if let Some(slot) = out.get_mut(..tag) {
            slot.copy_from_slice(full.get(..tag).unwrap_or_default());
        }
    }

    /// RFC 7714 §8: seal `buffer` (plaintext, with `aead::TAG` octets of room
    /// after it for the tag) in place under the RTP AAD -- the header, up to
    /// and including any extension.
    fn aead_seal_rtp(
        &self,
        header: &[u8],
        ssrc: u32,
        roc: u32,
        seq: u16,
        buffer: &mut [u8],
    ) -> Result<(), Exhausted> {
        let iv = self.aead_rtp_iv(ssrc, roc, seq);
        let plain_len = buffer.len().saturating_sub(aead::TAG);
        let (plaintext, tag_slot) = buffer.split_at_mut(plain_len);
        let tag = self.gcm().seal(&iv, header, plaintext)?;
        if let Some(slot) = tag_slot.get_mut(..aead::TAG) {
            slot.copy_from_slice(&tag);
        }
        Ok(())
    }

    /// The inverse: `buffer` holds ciphertext followed by its tag, verified
    /// and decrypted in place under the RTP AAD.
    fn aead_open_rtp(
        &self,
        header: &[u8],
        ssrc: u32,
        roc: u32,
        seq: u16,
        buffer: &mut [u8],
    ) -> Result<(), TagMismatch> {
        let iv = self.aead_rtp_iv(ssrc, roc, seq);
        let split = buffer.len().saturating_sub(aead::TAG);
        let (ciphertext, tag_slot) = buffer.split_at_mut(split);
        let mut tag = [0_u8; aead::TAG];
        tag.copy_from_slice(tag_slot.get(..aead::TAG).unwrap_or(&[0; aead::TAG]));
        self.gcm().open(&iv, header, ciphertext, &tag)
    }

    /// RFC 7714 §9: seal `plaintext` (with `aead::TAG` octets of room after
    /// it) in place under the RTCP AAD -- the eight-octet header and the
    /// ESRTCP word -- when `encrypting`; otherwise the AAD is the header, the
    /// whole of `plaintext` and the word, and `plaintext` is left as it is,
    /// with only the tag written.
    fn aead_seal_rtcp(
        &self,
        header: &[u8],
        ssrc: u32,
        index: u32,
        word: u32,
        encrypting: bool,
        plaintext: &mut [u8],
    ) -> Result<(), Exhausted> {
        let iv = self.aead_rtcp_iv(ssrc, index);
        let body_len = plaintext.len().saturating_sub(aead::TAG);
        let mut aad = Vec::with_capacity(header.len() + body_len + 4);
        aad.extend_from_slice(header);
        if !encrypting {
            aad.extend_from_slice(plaintext.get(..body_len).unwrap_or_default());
        }
        aad.extend_from_slice(&word.to_be_bytes());

        let (body, tag_slot) = plaintext.split_at_mut(body_len);
        let sealed = if encrypting { body } else { &mut [][..] };
        let tag = self.gcm().seal(&iv, &aad, sealed)?;
        if let Some(slot) = tag_slot.get_mut(..aead::TAG) {
            slot.copy_from_slice(&tag);
        }
        Ok(())
    }

    /// The inverse: `buffer` holds the RTCP payload (ciphertext when
    /// `encrypted`, plaintext otherwise) followed by its tag, verified and
    /// decrypted in place.
    fn aead_open_rtcp(
        &self,
        header: &[u8],
        ssrc: u32,
        index: u32,
        word: u32,
        encrypted: bool,
        buffer: &mut [u8],
    ) -> Result<(), TagMismatch> {
        let iv = self.aead_rtcp_iv(ssrc, index);
        let body_len = buffer.len().saturating_sub(aead::TAG);
        let mut tag = [0_u8; aead::TAG];
        tag.copy_from_slice(
            buffer
                .get(body_len..body_len + aead::TAG)
                .unwrap_or(&[0; aead::TAG]),
        );

        let mut aad = Vec::with_capacity(header.len() + body_len + 4);
        aad.extend_from_slice(header);
        if !encrypted {
            aad.extend_from_slice(buffer.get(..body_len).unwrap_or_default());
        }
        aad.extend_from_slice(&word.to_be_bytes());

        let (body, _) = buffer.split_at_mut(body_len);
        let opened = if encrypted { body } else { &mut [][..] };
        self.gcm().open(&iv, &aad, opened, &tag)
    }
}

/// The session keys, re-derived when the key derivation rate says so.
struct Derived {
    master: Master,
    suite: Suite,
    rate: Rate,
    /// `None` when the master key or salt is not the suite's width: nothing
    /// is derived from it, and every packet is refused.
    current: Option<Current>,
}

/// The session keys of the current derivation, each with the phase it is for.
struct Current {
    rtp: Engine,
    rtp_phase: u64,
    rtcp: Engine,
    rtcp_phase: u64,
}

/// A derivation for a packet that has not authenticated yet: kept only once
/// it has.
type Candidate = Option<(u64, Engine)>;

impl Derived {
    fn new(policy: &Policy, master: Master) -> Self {
        let lengths = policy.suite.lengths();
        let current = master.fits_lengths(lengths).then(|| Current {
            rtp: Engine::new(policy.suite, &master.rtp_session(policy.rate, 0, lengths)),
            rtp_phase: 0,
            rtcp: Engine::new(policy.suite, &master.rtcp_session(policy.rate, 0, lengths)),
            rtcp_phase: 0,
        });
        Self {
            suite: policy.suite,
            rate: policy.rate,
            current,
            master,
        }
    }

    fn current(&self) -> Result<&Current, SrtpError> {
        self.current.as_ref().ok_or(SrtpError::KeyLength)
    }

    /// The SRTP engine for a packet this end sends, re-derived and kept when
    /// the index has moved into a new phase.
    fn rtp(&mut self, index: u64) -> Result<&Engine, SrtpError> {
        let candidate = self.rtp_candidate(index)?;
        self.commit_rtp(candidate);
        Ok(&self.current()?.rtp)
    }

    /// The SRTCP engine for a packet this end sends.
    fn rtcp(&mut self, index: u32) -> Result<&Engine, SrtpError> {
        let candidate = self.rtcp_candidate(index)?;
        self.commit_rtcp(candidate);
        Ok(&self.current()?.rtcp)
    }

    /// A fresh SRTP derivation when `index` is in another phase than the one
    /// kept, and `None` when the kept one serves. Nothing is replaced here:
    /// an arriving packet's index is only a claim until its tag verifies, and
    /// a forged one must not be able to make the receiver throw away the keys
    /// the genuine stream is using.
    fn rtp_candidate(&self, index: u64) -> Result<Candidate, SrtpError> {
        let current = self.current()?;
        let phase = self.rate.phase_of(index);
        Ok((phase != current.rtp_phase).then(|| {
            let session = self
                .master
                .rtp_session(self.rate, index, self.suite.lengths());
            (phase, Engine::new(self.suite, &session))
        }))
    }

    /// As [`Derived::rtp_candidate`], for SRTCP.
    fn rtcp_candidate(&self, index: u32) -> Result<Candidate, SrtpError> {
        let current = self.current()?;
        let phase = self.rate.phase_of(u64::from(index));
        Ok((phase != current.rtcp_phase).then(|| {
            let session = self
                .master
                .rtcp_session(self.rate, index, self.suite.lengths());
            (phase, Engine::new(self.suite, &session))
        }))
    }

    /// The engine a packet is processed with: the candidate when there is
    /// one, the kept one otherwise.
    fn engine<'a>(current: &'a Engine, candidate: &'a Candidate) -> &'a Engine {
        candidate.as_ref().map_or(current, |(_, engine)| engine)
    }

    fn commit_rtp(&mut self, candidate: Candidate) {
        if let (Some(current), Some((phase, engine))) = (self.current.as_mut(), candidate) {
            current.rtp = engine;
            current.rtp_phase = phase;
        }
    }

    fn commit_rtcp(&mut self, candidate: Candidate) {
        if let (Some(current), Some((phase, engine))) = (self.current.as_mut(), candidate) {
            current.rtcp = engine;
            current.rtcp_phase = phase;
        }
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

    /// Protect under different terms from the same master key, keeping every
    /// counter where it is. See [`Rekeyed::Terms`] for why it has to keep
    /// them: the session keys do not depend on what changed, so the index is
    /// the only thing stopping a keystream from being spent twice.
    ///
    /// `master` is the key already in use, handed in again because a [`Master`]
    /// cannot be copied out of the one this holds — it zeroises on drop and
    /// has no other way out.
    pub fn retune(&mut self, policy: Policy, master: Master) {
        self.keys = Derived::new(&policy, master);
        self.policy = policy;
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
    /// Refuses a malformed header, a buffer with no room, a sequence number
    /// that does not move the packet index forward
    /// ([`SrtpError::IndexNotAdvancing`]: the same one again, or one behind
    /// the last), a master key of the wrong width for the suite, and — the
    /// one worth handling rather than logging — a master key that has
    /// secured as many packets as §9.2 allows. Nothing refused moves the
    /// index.
    pub fn protect_rtp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        self.keys.current()?;
        if self.rtp_packets >= self.policy.allowance(RTP_LIMIT) {
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
        let (index, sent) = self
            .rtp
            .next(sequence)
            .ok_or(SrtpError::IndexNotAdvancing)?;
        let roc = sent.rollover();

        // RFC 7714 §8.2: every AEAD-protected SRTP packet is both encrypted
        // and authenticated, in the one call that does both; the cipher's
        // sixteen-octet tag ends up embedded in what this function's other
        // branch treats as the payload, ahead of the MKI, rather than in a
        // trailing field of its own
        let mut at = if self.policy.suite.is_aead() {
            let sealed_end = len + aead::TAG;
            let got = packet.len();
            let (head, buffer) = packet
                .get_mut(..sealed_end)
                .ok_or(SrtpError::NoRoom {
                    need: sealed_end,
                    got,
                })?
                .split_at_mut(header);
            self.keys
                .rtp(index)?
                .aead_seal_rtp(head, ssrc, roc, sequence, buffer)?;
            sealed_end
        } else {
            if self.policy.encrypt_rtp {
                let (head, payload) = packet
                    .get_mut(..len)
                    .ok_or(SrtpError::Malformed)?
                    .split_at_mut(header);
                self.keys.rtp(index)?.encrypt_rtp(
                    self.policy.suite,
                    head,
                    ssrc,
                    index,
                    roc,
                    payload,
                )?;
            }
            len
        };

        if let Some(mki) = self.policy.mki {
            mki.write(packet.get_mut(at..).unwrap_or_default());
            at += mki.len();
        }
        if !self.policy.suite.is_aead() && self.policy.authenticate_rtp {
            let tag = self.policy.suite.tag();
            let mut bytes = [0_u8; sha1::DIGEST];
            self.keys.rtp(index)?.tag(
                &[packet.get(..len).unwrap_or_default(), &roc.to_be_bytes()],
                tag,
                &mut bytes,
            );
            if let Some(slot) = packet.get_mut(at..at + tag) {
                slot.copy_from_slice(bytes.get(..tag).unwrap_or_default());
            }
            at += tag;
        }

        self.rtp = sent;
        self.rtp_packets += 1;
        Ok(at)
    }

    /// Protect the RTCP compound packet occupying the first `len` octets.
    ///
    /// # Errors
    ///
    /// As `protect_rtp`, with §9.2's much lower SRTCP limit.
    pub fn protect_rtcp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        self.keys.current()?;
        if self.rtcp_packets >= self.policy.allowance(RTCP_LIMIT) {
            return Err(SrtpError::KeyExhausted);
        }
        // a length past the end of the buffer is refused before anything is
        // added to it, as protect_rtp refuses it
        if len < RTCP_HEADER || len > packet.len() {
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

        // RFC 7714 §9.2/§9.3: the AEAD suites always seal, whether or not the
        // packet is encrypted -- E=0 authenticates the whole packet as
        // associated data over an empty plaintext, producing a cipher that is
        // the tag alone. Either way the cipher (ciphertext, or nothing, plus
        // the sixteen-octet tag) sits right after the header, *before* the
        // ESRTCP word -- the reverse of where the HMAC tag goes below.
        let mut at = if self.policy.suite.is_aead() {
            let sealed_end = len + aead::TAG;
            let got = packet.len();
            let (head, body) = packet
                .get_mut(..sealed_end)
                .ok_or(SrtpError::NoRoom {
                    need: sealed_end,
                    got,
                })?
                .split_at_mut(RTCP_HEADER);
            self.keys.rtcp(index)?.aead_seal_rtcp(
                head,
                ssrc,
                index,
                word,
                self.policy.encrypt_rtcp,
                body,
            )?;
            sealed_end
        } else {
            if self.policy.encrypt_rtcp {
                let (head, payload) = packet
                    .get_mut(..len)
                    .ok_or(SrtpError::Malformed)?
                    .split_at_mut(RTCP_HEADER);
                self.keys.rtcp(index)?.encrypt_rtcp(
                    self.policy.suite,
                    head,
                    ssrc,
                    index,
                    word,
                    payload,
                )?;
            }
            len
        };

        if let Some(slot) = packet.get_mut(at..at + RTCP_INDEX) {
            slot.copy_from_slice(&word.to_be_bytes());
        }
        at += RTCP_INDEX;

        if !self.policy.suite.is_aead() {
            // the tag covers the packet and the index word but not the MKI,
            // so it is computed here, before the MKI moves `at` along
            let tag = self.policy.suite.rtcp_tag();
            let mut bytes = [0_u8; sha1::DIGEST];
            self.keys
                .rtcp(index)?
                .tag(&[packet.get(..at).unwrap_or_default()], tag, &mut bytes);
            if let Some(mki) = self.policy.mki {
                mki.write(packet.get_mut(at..).unwrap_or_default());
                at += mki.len();
            }
            if let Some(slot) = packet.get_mut(at..at + tag) {
                slot.copy_from_slice(bytes.get(..tag).unwrap_or_default());
            }
            at += tag;
        } else if let Some(mki) = self.policy.mki {
            mki.write(packet.get_mut(at..).unwrap_or_default());
            at += mki.len();
        }

        // §3.4: "incremented by one, modulo 2^31, after each SRTCP packet is
        // sent", and never reset, which is why the counter is separate from
        // the limit above
        self.rtcp_index = (self.rtcp_index + 1) % (1 << 31);
        self.rtcp_packets += 1;
        Ok(at)
    }
}

/// One remote source's index and replay state.
#[derive(Debug, Clone, Copy)]
struct Stream {
    index: Receiving,
    replay: Replay,
}

/// How many remote synchronization sources one receive context keeps a
/// rollover counter and a replay list for.
///
/// RFC 3711 §3.2.3 identifies a cryptographic context by its SSRC, and RFC
/// 4568 §6.4.2 has every source a peer sends share the one `a=crypto` line, so
/// each source needs state of its own. A source that loses its replay list
/// takes a recording of what it already delivered as new, and one that loses
/// its rollover counter has everything it sends after its first wrap refused
/// as forged.
///
/// Only a packet that authenticates takes a slot, so nothing a forger sends
/// can fill the table. A peer that has sent from more sources than this under
/// one master key has the one heard from least recently give way, which is
/// never the one carrying the call. What the source that gave way leaves
/// behind is its highest index, in [`Forgotten`]: heard from again, it
/// carries on from there, its rollover counter with it, and nothing at or
/// below that index is taken as new. Every new master key starts a table of
/// its own.
const SOURCES: usize = 8;

/// How many sources that gave way in [`Sources`] one receive context still
/// remembers the highest index of.
///
/// Bounded like the table itself. A peer would have to send authenticated
/// packets from this many more sources than [`SOURCES`] under one master key
/// before the oldest of these is lost too, and with it the record that keeps
/// a recording of that source from being taken as new.
const FORGOTTEN: usize = 32;

/// The highest index of each source that gave way in [`Sources`], most
/// recent last, overwritten oldest first.
#[derive(Debug, Clone, Copy)]
struct Forgotten {
    slots: [Option<(u32, u64)>; FORGOTTEN],
    next: usize,
}

impl Forgotten {
    const fn new() -> Self {
        Self {
            slots: [None; FORGOTTEN],
            next: 0,
        }
    }

    /// The highest index `ssrc` had reached when it gave way, if it did.
    fn get(&self, ssrc: u32) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .find(|(source, _)| *source == ssrc)
            .map(|(_, highest)| *highest)
    }

    /// Remember where `ssrc` had got to: in its own entry when it gave way
    /// before, otherwise in place of the oldest.
    fn note(&mut self, ssrc: u32, highest: u64) {
        let own = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|(source, _)| source == ssrc));
        let at = own.unwrap_or(self.next);
        if let Some(slot) = self.slots.get_mut(at) {
            *slot = Some((ssrc, highest));
        }
        if own.is_none() {
            self.next = (self.next + 1) % FORGOTTEN;
        }
    }
}

/// One source's state, and when it last authenticated a packet.
#[derive(Debug, Clone, Copy)]
struct Heard<T> {
    ssrc: u32,
    state: T,
    last: u64,
}

/// Per-source receive state for at most [`SOURCES`] sources, held in place.
#[derive(Debug, Clone, Copy)]
struct Sources<T> {
    slots: [Option<Heard<T>>; SOURCES],
    /// Counts what has been stored, so the source heard from least recently
    /// is the one with the smallest mark.
    clock: u64,
}

impl<T: Copy> Sources<T> {
    fn new() -> Self {
        Self {
            slots: [None; SOURCES],
            clock: 0,
        }
    }

    /// What the last authenticated packet from `ssrc` left its state as.
    fn get(&self, ssrc: u32) -> Option<T> {
        self.slots
            .iter()
            .flatten()
            .find(|heard| heard.ssrc == ssrc)
            .map(|heard| heard.state)
    }

    /// The state of the source heard from most recently.
    fn latest(&self) -> Option<T> {
        self.slots
            .iter()
            .flatten()
            .max_by_key(|heard| heard.last)
            .map(|heard| heard.state)
    }

    fn is_empty(&self) -> bool {
        self.slots.iter().all(Option::is_none)
    }

    /// Keep what an authenticated packet left `ssrc` as: in the slot it
    /// already has, in an empty one, or in place of the source heard from
    /// least recently, which is handed back.
    fn put(&mut self, ssrc: u32, state: T) -> Option<(u32, T)> {
        self.clock = self.clock.saturating_add(1);
        let own = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|heard| heard.ssrc == ssrc));
        let empty = self.slots.iter().position(Option::is_none);
        let stalest = self
            .slots
            .iter()
            .enumerate()
            .min_by_key(|(_, slot)| slot.map_or(0, |heard| heard.last))
            .map(|(at, _)| at);
        let slot = own
            .or(empty)
            .or(stalest)
            .and_then(|at| self.slots.get_mut(at))?;
        slot.replace(Heard {
            ssrc,
            state,
            last: self.clock,
        })
        .filter(|gone| gone.ssrc != ssrc)
        .map(|gone| (gone.ssrc, gone.state))
    }
}

/// The receiving half of an SRTP session.
pub struct Unprotector {
    policy: Policy,
    keys: Derived,
    rtp: Sources<Stream>,
    rtcp: Sources<Replay>,
    rtp_forgotten: Forgotten,
    rtcp_forgotten: Forgotten,
    initial: u32,
    /// The SRTP and SRTCP packets opened under this master key, held to the
    /// lifetime its owner declared ([`Policy::lifetime`]).
    rtp_opened: u64,
    rtcp_opened: u64,
}

impl Unprotector {
    /// An unprotector for what one peer sends.
    #[must_use]
    pub fn new(policy: Policy, master: Master) -> Self {
        Self {
            keys: Derived::new(&policy, master),
            policy,
            rtp: Sources::new(),
            rtcp: Sources::new(),
            rtp_forgotten: Forgotten::new(),
            rtcp_forgotten: Forgotten::new(),
            initial: 0,
            rtp_opened: 0,
            rtcp_opened: 0,
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

    /// Open under different terms from the same master key, keeping every
    /// source's index and replay window where they are. The mirror of
    /// [`Protector::retune`], and it keeps the window for a second reason
    /// besides the keystream: a fresh window accepts a packet this stream has
    /// already taken.
    pub fn retune(&mut self, policy: Policy, master: Master) {
        self.keys = Derived::new(&policy, master);
        self.policy = policy;
    }

    /// The rollover counter of the source heard from most recently, which is
    /// what a second receiver of that stream would have to be given (§3.3.1).
    #[must_use]
    pub fn rollover(&self) -> u32 {
        self.rtp
            .latest()
            .map_or(self.initial, |stream| stream.index.rollover())
    }

    /// The state a packet from `ssrc` is judged against: the source's own
    /// when it has been heard from, what it had reached when it has been
    /// heard from and then gave way to other sources, a fresh one when it
    /// has not been heard from at all.
    ///
    /// A copy either way, and nothing is written back until the tag verifies,
    /// so a forged packet naming an unused SSRC takes no slot and a forged
    /// packet naming a known one moves nothing of that source's state.
    ///
    /// A new source starts from a rollover counter of zero, which RFC 4568
    /// §6.4 makes the counter of every source "at the time that each SSRC
    /// commences sending packets". Only the first source of a receiver that
    /// joined a session in progress starts from the counter it was given.
    fn stream_for(&self, ssrc: u32) -> Stream {
        if let Some(stream) = self.rtp.get(ssrc) {
            return stream;
        }
        if let Some(highest) = self.rtp_forgotten.get(ssrc) {
            return Stream {
                index: Receiving::resumed(highest),
                replay: Replay::resumed(highest),
            };
        }
        Stream {
            index: if self.rtp.is_empty() {
                Receiving::joining(self.initial)
            } else {
                Receiving::default()
            },
            replay: Replay::default(),
        }
    }

    /// The SRTCP replay list a packet from `ssrc` is judged against, on the
    /// same terms as [`Unprotector::stream_for`].
    fn rtcp_replay_for(&self, ssrc: u32) -> Replay {
        self.rtcp
            .get(ssrc)
            .or_else(|| self.rtcp_forgotten.get(ssrc).map(Replay::resumed))
            .unwrap_or_default()
    }

    fn keep_rtp(&mut self, ssrc: u32, stream: Stream) {
        if let Some((gone, state)) = self.rtp.put(ssrc, stream)
            && let Some(highest) = state.replay.highest()
        {
            self.rtp_forgotten.note(gone, highest);
        }
    }

    fn keep_rtcp(&mut self, ssrc: u32, replay: Replay) {
        if let Some((gone, state)) = self.rtcp.put(ssrc, replay)
            && let Some(highest) = state.highest()
        {
            self.rtcp_forgotten.note(gone, highest);
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
    /// A short or malformed packet, a replay, a tag that does not match, a
    /// master key of the wrong width for the suite, and
    /// [`SrtpError::KeyExhausted`] once the key has opened as many packets
    /// as the lifetime its owner declared allows.
    pub fn unprotect_rtp(&mut self, packet: &mut [u8]) -> Result<usize, SrtpError> {
        self.keys.current()?;
        if self.rtp_opened >= self.policy.allowance(RTP_LIMIT) {
            return Err(SrtpError::KeyExhausted);
        }
        let is_aead = self.policy.suite.is_aead();
        let tag = if is_aead {
            aead::TAG
        } else if self.policy.authenticate_rtp {
            self.policy.suite.tag()
        } else {
            0
        };
        // `body` is the plaintext length -- header plus payload -- in both
        // families: a MAC suite's tag sits in a trailing field of its own,
        // after the MKI, while an AEAD suite's sits inside the cipher, right
        // before the MKI; either way it is `tag` octets wide and this is
        // where it and the MKI both start counting back from
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

        let candidate = self.keys.rtp_candidate(estimate.index)?;
        let engine = Derived::engine(&self.keys.current()?.rtp, &candidate);
        if is_aead {
            let sealed_end = body + aead::TAG;
            self.check_mki(packet, sealed_end)?;
            let (head, cipher_and_tag) = packet
                .get_mut(..sealed_end)
                .ok_or(SrtpError::Malformed)?
                .split_at_mut(header);
            engine
                .aead_open_rtp(head, ssrc, estimate.rollover(), sequence, cipher_and_tag)
                .map_err(|TagMismatch| SrtpError::NotAuthentic)?;
        } else {
            self.check_mki(packet, body)?;
            if tag > 0 {
                let mut expected = [0_u8; sha1::DIGEST];
                engine.tag(
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
                engine.encrypt_rtp(
                    self.policy.suite,
                    head,
                    ssrc,
                    estimate.index,
                    estimate.rollover(),
                    payload,
                )?;
            }
        }

        self.keys.commit_rtp(candidate);
        stream.index.accept(estimate);
        stream.replay.record(estimate.index);
        self.keep_rtp(ssrc, stream);
        self.rtp_opened += 1;
        Ok(body)
    }

    /// Verify and decrypt an SRTCP packet in place, returning the length of
    /// the RTCP compound packet inside it.
    ///
    /// # Errors
    ///
    /// As `unprotect_rtp`.
    pub fn unprotect_rtcp(&mut self, packet: &mut [u8]) -> Result<usize, SrtpError> {
        self.keys.current()?;
        if self.rtcp_opened >= self.policy.allowance(RTCP_LIMIT) {
            return Err(SrtpError::KeyExhausted);
        }
        let tag = self.policy.suite.rtcp_tag();
        if self.policy.suite.is_aead() {
            let opened = self.unprotect_rtcp_aead(packet, tag)?;
            self.rtcp_opened += 1;
            return Ok(opened);
        }
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
        // moves only once the tag has verified. One list per sending source,
        // since §3.4 keeps SRTCP's list beside the SRTP one of the same context
        let mut replay = self.rtcp_replay_for(ssrc);
        if !replay.accepts(u64::from(index)) {
            return Err(SrtpError::Replayed);
        }

        self.check_mki(packet, with_index)?;
        let candidate = self.keys.rtcp_candidate(index)?;
        let engine = Derived::engine(&self.keys.current()?.rtcp, &candidate);
        let mut expected = [0_u8; sha1::DIGEST];
        engine.tag(
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
            engine.encrypt_rtcp(self.policy.suite, head, ssrc, index, word, payload)?;
        }

        self.keys.commit_rtcp(candidate);
        replay.record(u64::from(index));
        self.keep_rtcp(ssrc, replay);
        self.rtcp_opened += 1;
        Ok(body)
    }

    /// The AEAD half of [`Self::unprotect_rtcp`]: the cipher (ciphertext, or
    /// nothing, plus the sixteen-octet tag) sits right after the RTCP body,
    /// *before* the ESRTCP word -- the reverse of a MAC suite's layout, where
    /// the word comes first and the tag trails everything but the MKI.
    fn unprotect_rtcp_aead(&mut self, packet: &mut [u8], tag: usize) -> Result<usize, SrtpError> {
        let trailer = tag + RTCP_INDEX + self.policy.mki_len();
        let body = packet
            .len()
            .checked_sub(trailer)
            .filter(|body| *body >= RTCP_HEADER)
            .ok_or(SrtpError::TooShort { got: packet.len() })?;
        let sealed_end = body + tag;
        let word = read_u32(packet, sealed_end);
        let index = word & !RTCP_ENCRYPTED;
        let ssrc = read_u32(packet, 4);

        let mut replay = self.rtcp_replay_for(ssrc);
        if !replay.accepts(u64::from(index)) {
            return Err(SrtpError::Replayed);
        }

        self.check_mki(packet, sealed_end + RTCP_INDEX)?;
        let (head, buffer) = packet
            .get_mut(..sealed_end)
            .ok_or(SrtpError::Malformed)?
            .split_at_mut(RTCP_HEADER);
        let candidate = self.keys.rtcp_candidate(index)?;
        Derived::engine(&self.keys.current()?.rtcp, &candidate)
            .aead_open_rtcp(head, ssrc, index, word, word & RTCP_ENCRYPTED != 0, buffer)
            .map_err(|TagMismatch| SrtpError::NotAuthentic)?;

        self.keys.commit_rtcp(candidate);
        replay.record(u64::from(index));
        self.keep_rtcp(ssrc, replay);
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

/// The keys for one call, one direction each way.
///
/// RFC 4568 §7.1.1: "The inline parameter conveys the SRTP master key used by
/// an endpoint to encrypt the SRTP and SRTCP streams transmitted by that
/// endpoint ... the receiver MUST NOT use that same key for the SRTP or SRTCP
/// packets that it sends". So there are two master keys and two contexts, and
/// this is the pair.
pub struct Security {
    sending: Protector,
    receiving: Unprotector,
    retiring: Option<Retiring>,
}

/// The receive context a re-key replaced, and what is left of its grace.
struct Retiring {
    context: Unprotector,
    left: u32,
}

/// What a re-negotiation did to one direction's keying, which is what decides
/// the fate of the packet index.
///
/// The distinction is not cosmetic. §4.3.1 derives the session keys from the
/// master key, the master salt and the index, and from nothing else — not the
/// crypto suite, not the tag length. So two crypto lines that name the same
/// `inline:` produce the same keystream however much else about them differs,
/// and a stream that restarted its index across such a change would encrypt a
/// second packet under a keystream it had already spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rekeyed {
    /// A master key that has never been used here. The index starts again:
    /// §9.1 asks that the triple (master key, SSRC, index) never repeat, and
    /// a key that has never been used cannot repeat one.
    Key,
    /// The same master key under terms that moved — `AES_CM_128_HMAC_SHA1_80`
    /// giving way to `_32`, say, which keeps the sixteen key octets and the
    /// fourteen salt octets and shortens only the tag. The transform follows;
    /// the index does not restart.
    Terms,
}

/// How many arriving RTP packets the previous receive context outlives a
/// re-key.
///
/// A peer re-keys by naming the new key in SDP and then using it, and the two
/// cross on the wire: the answer that carries the key is processed here before
/// the first packet protected with it arrives, and everything still in flight
/// is under the key it is replacing. Without a grace those packets are all
/// [`SrtpError::NotAuthentic`].
///
/// It must not last, either. A superseded master key that still opens packets
/// is a key whose replacement bought nothing. At the usual twenty milliseconds
/// a packet this is five seconds — longer than any crossing, shorter than any
/// call.
const GRACE: u32 = 250;

impl Security {
    /// The two halves. `sending` protects what this endpoint transmits and
    /// carries the key this endpoint offered; `receiving` opens what arrives
    /// and carries the key the peer offered.
    #[must_use]
    pub fn new(
        sending: Policy,
        sending_key: Master,
        receiving: Policy,
        receiving_key: Master,
    ) -> Self {
        Self {
            sending: Protector::new(sending, sending_key),
            receiving: Unprotector::new(receiving, receiving_key),
            retiring: None,
        }
    }

    /// Octets a protected RTP packet is longer than the packet it came from.
    #[must_use]
    pub const fn rtp_overhead(&self) -> usize {
        self.sending.rtp_overhead()
    }

    /// Octets a protected RTCP packet is longer than the packet it came from.
    #[must_use]
    pub const fn rtcp_overhead(&self) -> usize {
        self.sending.rtcp_overhead()
    }

    /// Protect an outgoing RTP packet in place.
    ///
    /// # Errors
    /// As [`Protector::protect_rtp`].
    pub fn protect_rtp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        self.sending.protect_rtp(packet, len)
    }

    /// Protect an outgoing RTCP packet in place.
    ///
    /// # Errors
    /// As [`Protector::protect_rtcp`].
    pub fn protect_rtcp(&mut self, packet: &mut [u8], len: usize) -> Result<usize, SrtpError> {
        self.sending.protect_rtcp(packet, len)
    }

    /// Verify and decrypt an arriving RTP packet in place.
    ///
    /// A packet that does not open under the current key is offered to the
    /// context a recent [`Security::rekey_remote`] retired, while that context
    /// still has grace. Trying twice is sound because a failed attempt leaves
    /// the datagram byte-identical: [`Unprotector::unprotect_rtp`] checks the
    /// replay window against a copy and verifies the tag before it decrypts
    /// anything, and so does the GCM open of the AEAD suites. A refactor or a
    /// dependency that decrypted first would break this, and
    /// `a_packet_that_does_not_open_is_left_as_it_arrived` would say so.
    ///
    /// # Errors
    /// As [`Unprotector::unprotect_rtp`], reported for the current key even
    /// when a retired one was tried as well.
    pub fn unprotect_rtp(&mut self, packet: &mut [u8]) -> Result<usize, SrtpError> {
        let fresh = self.receiving.unprotect_rtp(packet);
        if fresh.is_ok() {
            // the peer is using the key it named, so the one it replaced has
            // nothing left to open
            self.retiring = None;
            return fresh;
        }
        let Some(retiring) = self.retiring.as_mut() else {
            return fresh;
        };
        retiring.left = retiring.left.saturating_sub(1);
        let opened = retiring.context.unprotect_rtp(packet);
        if retiring.left == 0 {
            self.retiring = None;
        }
        opened.or(fresh)
    }

    /// Verify and decrypt an arriving RTCP packet in place.
    ///
    /// Reports travel far less often than media, so the grace is counted in
    /// RTP packets alone; an SRTCP packet is offered to a retired context for
    /// as long as one is there.
    ///
    /// # Errors
    /// As [`Unprotector::unprotect_rtcp`], reported for the current key.
    pub fn unprotect_rtcp(&mut self, packet: &mut [u8]) -> Result<usize, SrtpError> {
        let fresh = self.receiving.unprotect_rtcp(packet);
        if fresh.is_ok() {
            self.retiring = None;
            return fresh;
        }
        match self.retiring.as_mut() {
            Some(retiring) => retiring.context.unprotect_rtcp(packet).or(fresh),
            None => fresh,
        }
    }

    /// Send under what a re-negotiation settled on, from here on.
    ///
    /// On [`Rekeyed::Key`] a plain replacement, counters and all: the index
    /// starting again repeats nothing, because the key it counts under has
    /// never been used. On [`Rekeyed::Terms`] the transform is replaced and
    /// the index carries on, for the reason [`Rekeyed`] gives.
    ///
    /// There is no crossing to cover on this side. This endpoint decides when
    /// it starts stamping with what the negotiation settled on, and that is
    /// now.
    ///
    /// A master key that is the one already in use is new terms whatever
    /// `what` says: under it the index must not start again (§9.1), and the
    /// SRTCP index is never reset (§3.4).
    pub fn rekey_local(&mut self, policy: Policy, master: Master, what: Rekeyed) {
        let what = if self.sending.keys.master.same_as(&master) {
            Rekeyed::Terms
        } else {
            what
        };
        match what {
            // the Protector going out of scope drops its derived session keys
            // and the master they came from, both of which zeroise
            Rekeyed::Key => self.sending = Protector::new(policy, master),
            Rekeyed::Terms => self.sending.retune(policy, master),
        }
    }

    /// Open arriving packets with what a re-negotiation settled on, without
    /// losing the ones already in flight under what it replaced.
    ///
    /// On [`Rekeyed::Key`] the peer's answer reaches us before the peer's
    /// first packet under the key it names, so the context being replaced is
    /// kept for a bounded run of packets and dropped the moment one authenticates
    /// under the new key — whichever comes first.
    ///
    /// On [`Rekeyed::Terms`] there is nothing to stage: every packet in
    /// flight is under the key we still hold, and only the tag length around
    /// it moved.
    ///
    /// A master key that is the one already in use is new terms here too,
    /// whatever `what` says: a fresh context under it would have forgotten
    /// every replay list, and taken a recording of the stream as new.
    pub fn rekey_remote(&mut self, policy: Policy, master: Master, what: Rekeyed) {
        let what = if self.receiving.keys.master.same_as(&master) {
            Rekeyed::Terms
        } else {
            what
        };
        match what {
            Rekeyed::Key => {
                let previous =
                    core::mem::replace(&mut self.receiving, Unprotector::new(policy, master));
                self.retiring = Some(Retiring {
                    context: previous,
                    left: GRACE,
                });
            }
            Rekeyed::Terms => self.receiving.retune(policy, master),
        }
    }

    /// The rollover counter of the stream being sent, which a second receiver
    /// joining late would have to be given (§3.3.1).
    #[must_use]
    pub const fn rollover(&self) -> u32 {
        self.sending.rollover()
    }
}

impl core::fmt::Debug for Security {
    /// Names the type and nothing else. Everything inside is key material or
    /// derived from it, and a value that cannot be printed cannot be printed
    /// by accident.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Security { .. }")
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
pub(crate) fn equal(a: &[u8], b: &[u8]) -> bool {
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
    use zeroize::Zeroizing;

    use super::{
        GRACE, Master, Mki, Policy, Protector, RTCP_INDEX, Rate, Rekeyed, SOURCES, Security,
        SrtpError, Suite, Unprotector,
    };

    const SSRC: u32 = 0xdead_beef;

    fn master() -> Master {
        Master::new(&[0x11; 16], &[0x22; 14])
    }

    fn other_master() -> Master {
        Master::new(&[0x33; 16], &[0x22; 14])
    }

    /// A master key and salt sized for `suite` -- a wider key for the
    /// AES-256 suites, a narrower salt for the AEAD ones -- filled with the
    /// same two repeating octets [`master`] uses, so this agrees with it
    /// exactly for `Suite::AesCm80`, the suite every other test here that
    /// does not loop over suites is written against.
    fn master_for(suite: Suite) -> Master {
        Master::new(
            &vec![0x11_u8; suite.key_len()],
            &vec![0x22_u8; suite.salt_len()],
        )
    }

    fn pair(policy: Policy) -> (Protector, Unprotector) {
        (
            Protector::new(policy, master_for(policy.suite)),
            Unprotector::new(policy, master_for(policy.suite)),
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
        for suite in Suite::STRENGTH {
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
        for suite in Suite::STRENGTH {
            let policy = Policy::new(suite);
            let (mut protector, mut unprotector) = pair(policy);
            let plain = compound();

            let mut buffer = room(&plain, protector.rtcp_overhead());
            let len = protector
                .protect_rtcp(&mut buffer, plain.len())
                .expect("protects");
            // four octets of index and the suite's own SRTCP tag: ten octets
            // of HMAC for every MAC suite (§5.2 forbids shortening SRTCP's,
            // whatever the SRTP tag says) or sixteen of embedded AEAD tag
            assert_eq!(
                len,
                plain.len() + RTCP_INDEX + suite.rtcp_tag(),
                "{suite:?}"
            );
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

    // RFC 4568 §6.1 gives an identifier a value and the width of the field it
    // travels in. A value wider than its field was written truncated and
    // compared whole, so a policy the constructor had accepted could not open
    // a single packet protected under it
    #[test]
    fn an_identifier_whose_value_does_not_fit_its_length_is_refused() {
        assert!(Mki::new(255, 1).is_some());
        assert!(
            Mki::new(256, 1).is_none(),
            "a value of 256 in a one-octet field"
        );
        assert!(Mki::new(1 << 32, 4).is_none());
        assert!(Mki::new(u128::MAX, 16).is_some());
    }

    // protect_rtp refuses a length past the end of its buffer before it adds
    // anything to it, and protect_rtcp has to as well
    #[test]
    fn a_length_past_the_end_of_the_buffer_is_refused_on_both_protocols() {
        let (mut protector, _) = pair(Policy::new(Suite::AesCm80));
        let mut buffer = vec![0_u8; 64];
        assert_eq!(
            protector.protect_rtp(&mut buffer, usize::MAX),
            Err(SrtpError::TooShort { got: usize::MAX })
        );
        assert_eq!(
            protector.protect_rtcp(&mut buffer, usize::MAX),
            Err(SrtpError::TooShort { got: usize::MAX })
        );
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
        assert_eq!(Suite::Aes256Cm80.name(), "AES_256_CM_HMAC_SHA1_80");
        assert_eq!(Suite::Aes256Cm32.name(), "AES_256_CM_HMAC_SHA1_32");
        assert_eq!(Suite::AeadAes128Gcm.name(), "AEAD_AES_128_GCM");
        assert_eq!(Suite::AeadAes256Gcm.name(), "AEAD_AES_256_GCM");
        for suite in Suite::STRENGTH {
            assert_eq!(Suite::from_name(suite.name()), Some(suite));
        }
        assert_eq!(
            Suite::from_name("aes_cm_128_hmac_sha1_80"),
            Some(Suite::AesCm80)
        );
        assert_eq!(
            Suite::from_name("aead_aes_256_gcm"),
            Some(Suite::AeadAes256Gcm)
        );
        assert_eq!(Suite::from_name("AES_CM_512_HMAC_SHA1_80"), None);
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
        // forward to the wrap in steps a receiver can follow
        tag_of(&mut protector, 30_000);
        tag_of(&mut protector, 60_000);
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
        // forward to the wrap in steps a receiver can follow
        body_of(&mut protector, 30_000);
        body_of(&mut protector, 60_000);
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

    // -- more than one source under one master key ----------------------------

    /// One packet from `ssrc`, protected by the context that sender keeps for
    /// it.
    fn sent_from(protector: &mut Protector, ssrc: u32, sequence: u16) -> Vec<u8> {
        let mut plain = packet(sequence, b"payload");
        if let Some(slot) = plain.get_mut(8..12) {
            slot.copy_from_slice(&ssrc.to_be_bytes());
        }
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector
            .protect_rtp(&mut buffer, plain.len())
            .expect("the packet protects");
        buffer.truncate(len);
        buffer
    }

    // RFC 3711 §3.2.3 names a context by its SSRC, and RFC 4568 §6.4.2 lets
    // every source a peer sends share one master key. A receiver that keeps a
    // replay list for one source at a time forgets the list of the source it
    // moved away from, and then takes a recording of that source as new
    #[test]
    fn a_replay_is_refused_after_the_peer_has_moved_to_another_source() {
        let policy = Policy::new(Suite::AesCm80);
        let mut first = Protector::new(policy, master());
        let mut second = Protector::new(policy, master());
        let mut unprotector = Unprotector::new(policy, master());

        let early = sent_from(&mut first, SSRC, 100);
        assert!(unprotector.unprotect_rtp(&mut early.clone()).is_ok());
        let later = sent_from(&mut second, 0x0bad_cafe, 7_000);
        assert!(unprotector.unprotect_rtp(&mut later.clone()).is_ok());

        assert_eq!(
            unprotector.unprotect_rtp(&mut early.clone()),
            Err(SrtpError::Replayed),
            "a recording of the first source was taken as new once a second \
             source had spoken"
        );
        assert_eq!(
            unprotector.unprotect_rtp(&mut later.clone()),
            Err(SrtpError::Replayed),
            "and the second source's list went the moment the first came back"
        );
    }

    // The same forgetting, costing the running source its rollover counter:
    // one packet from a second source, and every packet of the first after its
    // wrap is checked against a counter of zero and refused as forged
    #[test]
    fn a_second_source_does_not_cost_the_first_its_rollover_counter() {
        let policy = Policy::new(Suite::AesCm80);
        let mut running = Protector::new(policy, master());
        let mut other = Protector::new(policy, master());
        let mut unprotector = Unprotector::new(policy, master());

        for sequence in [65_534, 65_535, 0, 1] {
            let mut datagram = sent_from(&mut running, SSRC, sequence);
            assert!(
                unprotector.unprotect_rtp(&mut datagram).is_ok(),
                "sequence {sequence}"
            );
        }
        assert_eq!(unprotector.rollover(), 1, "the running source wrapped");

        let mut interleaved = sent_from(&mut other, 0x0bad_cafe, 20);
        assert!(unprotector.unprotect_rtp(&mut interleaved).is_ok());

        let mut next = sent_from(&mut running, SSRC, 2);
        assert_eq!(
            unprotector.unprotect_rtp(&mut next).map(|_| ()),
            Ok(()),
            "the running source lost its rollover counter to a packet from \
             another one"
        );
    }

    // The table is bounded, so at some point a source has to give way to a
    // new one. It has to be the one heard from least recently, which is never
    // the one carrying the call
    #[test]
    fn a_crowd_of_sources_does_not_displace_the_one_that_is_talking() {
        let policy = Policy::new(Suite::AesCm80);
        let mut running = Protector::new(policy, master());
        let mut unprotector = Unprotector::new(policy, master());

        let mut sequence = 65_534_u16;
        for _ in 0..4 {
            let mut datagram = sent_from(&mut running, SSRC, sequence);
            assert!(unprotector.unprotect_rtp(&mut datagram).is_ok());
            sequence = sequence.wrapping_add(1);
        }
        assert_eq!(unprotector.rollover(), 1, "the running source wrapped");

        let crowd = u32::try_from(SOURCES * 2).unwrap_or(u32::MAX);
        for source in 1..=crowd {
            let mut stranger = Protector::new(policy, master());
            let mut datagram = sent_from(&mut stranger, source, 10);
            assert!(
                unprotector.unprotect_rtp(&mut datagram).is_ok(),
                "source {source}"
            );

            let mut talking = sent_from(&mut running, SSRC, sequence);
            assert_eq!(
                unprotector.unprotect_rtp(&mut talking).map(|_| ()),
                Ok(()),
                "the running source gave way to source {source}"
            );
            sequence = sequence.wrapping_add(1);
        }
    }

    #[test]
    fn an_srtcp_replay_is_refused_after_the_peer_has_moved_to_another_source() {
        let (mut protector, mut unprotector) = pair(Policy::new(Suite::AesCm80));
        let report = |protector: &mut Protector, ssrc: u32| {
            let mut plain = compound();
            if let Some(slot) = plain.get_mut(4..8) {
                slot.copy_from_slice(&ssrc.to_be_bytes());
            }
            let mut buffer = room(&plain, protector.rtcp_overhead());
            let len = protector
                .protect_rtcp(&mut buffer, plain.len())
                .expect("the report protects");
            buffer.truncate(len);
            buffer
        };

        let early = report(&mut protector, SSRC);
        assert!(unprotector.unprotect_rtcp(&mut early.clone()).is_ok());
        let later = report(&mut protector, 0x0bad_cafe);
        assert!(unprotector.unprotect_rtcp(&mut later.clone()).is_ok());

        assert_eq!(
            unprotector.unprotect_rtcp(&mut early.clone()),
            Err(SrtpError::Replayed),
            "a recorded report from the first source was taken as new once a \
             second source had reported"
        );
    }

    // RFC 3711 §3.3.1 has a receiver joining a session already in progress
    // told the current rollover counter out of band, since nothing in a
    // packet's own sequence number says how many times it has wrapped. Only
    // the first source a receiver hears from is owed that counter — every
    // later source starts its own count at zero, from the point it starts
    // sending (§6.4 of RFC 4568)
    #[test]
    fn a_receiver_joining_late_starts_from_the_rollover_it_is_given() {
        let policy = Policy::new(Suite::AesCm80);
        let mut protector = Protector::new(policy, master());

        // wrap the sender's rollover counter to one before any receiver
        // exists, the way a session already running would have
        for sequence in [65_534, 65_535] {
            let plain = packet(sequence, b"warmup");
            let mut buffer = room(&plain, protector.rtp_overhead());
            protector
                .protect_rtp(&mut buffer, plain.len())
                .expect("the packet protects");
        }
        assert_eq!(protector.rollover(), 0, "not wrapped yet");

        let plain = packet(0, b"joined");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector
            .protect_rtp(&mut buffer, plain.len())
            .expect("the packet protects");
        assert_eq!(protector.rollover(), 1, "the sender has now wrapped");
        let wire = buffer.get(..len).unwrap_or_default().to_vec();

        // a receiver with no rollover counter of its own reads this low
        // sequence number as rollover zero, which is not what it was sent
        // under
        let mut fresh = Unprotector::new(policy, master());
        assert_eq!(
            fresh.unprotect_rtp(&mut wire.clone()),
            Err(SrtpError::NotAuthentic),
            "a fresh receiver guessed rollover zero for a packet sent under \
             rollover one"
        );

        // one given the sender's rollover counter out of band decodes it
        let mut joined = Unprotector::joining(policy, master(), 1);
        assert_eq!(joined.unprotect_rtp(&mut wire.clone()), Ok(plain.len()));
        assert_eq!(joined.rollover(), 1);
    }

    // -- re-keying a session that is already running -------------------------

    fn third_master() -> Master {
        Master::new(&[0x44; 16], &[0x22; 14])
    }

    /// One protected packet, ready to hand to an unprotector.
    fn sent(protector: &mut Protector, sequence: u16) -> Vec<u8> {
        let plain = packet(sequence, b"payload");
        let mut buffer = room(&plain, protector.rtp_overhead());
        let len = protector
            .protect_rtp(&mut buffer, plain.len())
            .expect("the packet protects");
        buffer.truncate(len);
        buffer
    }

    // §9.1 asks that (master key, SSRC, index) never repeat. A key that has
    // never been used cannot repeat one, so a genuine re-key is free to start
    // the index again — and has to, because carrying an advanced index over
    // would only make the two ends disagree about where the stream is
    /// One protected packet out of a whole session rather than out of a bare
    /// protector.
    fn issued(security: &mut Security, sequence: u16) -> Vec<u8> {
        let plain = packet(sequence, b"payload");
        let mut buffer = room(&plain, security.rtp_overhead());
        let len = security
            .protect_rtp(&mut buffer, plain.len())
            .expect("the packet protects");
        buffer.truncate(len);
        buffer
    }

    #[test]
    fn a_new_master_key_starts_the_packet_index_again() {
        let policy = Policy::new(Suite::AesCm80);
        let mut security = Security::new(policy, master(), policy, master());
        issued(&mut security, 65_535);
        issued(&mut security, 0);
        assert_eq!(security.rollover(), 1, "the stream wrapped");

        security.rekey_local(policy, other_master(), Rekeyed::Key);
        assert_eq!(
            security.rollover(),
            0,
            "a key that has never been used counts from zero"
        );

        // and the far end, keyed to match and with no rollover counter handed
        // to it out of band, hears the stream from where it now is
        let mut receiver = Unprotector::new(policy, other_master());
        let mut carried = issued(&mut security, 7);
        assert_eq!(
            receiver.unprotect_rtp(&mut carried).map(|_| ()),
            Ok(()),
            "the two ends disagree about where the stream is"
        );
    }

    // The same master key under a shorter tag: §4.3.1 derives the session
    // keys from the key, the salt and the index, and from none of what moved.
    // So the keystream is the one already in use, and an index that started
    // again would spend it twice — the two-time pad §9.1 calls catastrophic
    #[test]
    fn terms_that_move_under_the_same_key_do_not_restart_the_packet_index() {
        let mut security = Security::new(
            Policy::new(Suite::AesCm80),
            master(),
            Policy::new(Suite::AesCm80),
            master(),
        );
        let body = |security: &mut Security, sequence: u16| {
            let plain = packet(sequence, b"payload");
            let mut buffer = room(&plain, security.rtp_overhead());
            security
                .protect_rtp(&mut buffer, plain.len())
                .expect("the packet protects");
            buffer.get(12..plain.len()).unwrap_or_default().to_vec()
        };

        let before = body(&mut security, 100);
        // forward to the wrap in steps a receiver can follow
        body(&mut security, 30_000);
        body(&mut security, 60_000);
        body(&mut security, 65_535);
        body(&mut security, 0);
        assert_eq!(security.rollover(), 1, "the stream wrapped");

        // the far end answered with the same inline: and a shorter tag
        security.rekey_local(Policy::new(Suite::AesCm32), master(), Rekeyed::Terms);
        assert_eq!(security.rollover(), 1, "the index is not what moved");
        assert_ne!(
            before,
            body(&mut security, 100),
            "the same key, the same sequence number and the same payload \
             encrypted to the same octets: the index restarted"
        );
    }

    // A peer re-keys by naming the key in SDP and then using it, and the two
    // cross on the wire: the answer is processed here before the first packet
    // protected with it arrives. Without a grace every packet still in flight
    // is thrown away as forged
    #[test]
    fn a_peer_that_has_not_switched_to_its_new_key_yet_is_still_heard() {
        let policy = Policy::new(Suite::AesCm80);
        let mut before = Protector::new(policy, master());
        let mut after = Protector::new(policy, other_master());
        let mut security = Security::new(policy, master(), policy, master());

        security.rekey_remote(policy, other_master(), Rekeyed::Key);

        let mut crossing = sent(&mut before, 100);
        assert_eq!(
            security.unprotect_rtp(&mut crossing).map(|_| ()),
            Ok(()),
            "a packet sent before the far end saw our answer"
        );

        let mut switched = sent(&mut after, 101);
        assert_eq!(security.unprotect_rtp(&mut switched).map(|_| ()), Ok(()));

        // the far end has switched, so the key it left behind opens nothing
        let mut late = sent(&mut before, 102);
        assert_eq!(
            security.unprotect_rtp(&mut late),
            Err(SrtpError::NotAuthentic),
            "a key that has been replaced and proven replaced is still open"
        );
    }

    // The grace exists to cover a crossing, which takes packets, not minutes.
    // A superseded master key that goes on opening packets is a key whose
    // replacement bought nothing
    #[test]
    fn a_key_that_was_replaced_does_not_outlive_its_grace() {
        let policy = Policy::new(Suite::AesCm80);
        let mut before = Protector::new(policy, master());
        let mut stranger = Protector::new(policy, third_master());
        let mut security = Security::new(policy, master(), policy, master());

        security.rekey_remote(policy, other_master(), Rekeyed::Key);
        let mut early = sent(&mut before, 1);
        assert_eq!(
            security.unprotect_rtp(&mut early).map(|_| ()),
            Ok(()),
            "the grace is not there at all"
        );

        // packets that open under neither key still spend it
        for step in 0..GRACE {
            let sequence = 1_000_u32.saturating_add(step);
            let mut junk = sent(&mut stranger, u16::try_from(sequence).unwrap_or(u16::MAX));
            assert!(security.unprotect_rtp(&mut junk).is_err());
        }

        let mut late = sent(&mut before, 500);
        assert_eq!(
            security.unprotect_rtp(&mut late),
            Err(SrtpError::NotAuthentic),
            "the replaced key is still open after its grace ran out"
        );
    }

    /// A protected compound packet from `ssrc`, and the SRTCP index it went
    /// under.
    fn reported(protector: &mut Protector, ssrc: u32) -> (Vec<u8>, u32) {
        let mut plain = compound();
        if let Some(slot) = plain.get_mut(4..8) {
            slot.copy_from_slice(&ssrc.to_be_bytes());
        }
        let mut buffer = room(&plain, protector.rtcp_overhead());
        let len = protector
            .protect_rtcp(&mut buffer, plain.len())
            .expect("the report protects");
        buffer.truncate(len);
        let word = buffer
            .get(plain.len()..plain.len() + RTCP_INDEX)
            .and_then(|word| <[u8; 4]>::try_from(word).ok())
            .map_or(0, u32::from_be_bytes);
        (buffer, word & 0x7fff_ffff)
    }

    // §9.1: the same (key, SSRC, index) twice is the same keystream twice,
    // and under GCM the same nonce twice
    #[test]
    fn a_sequence_number_that_does_not_move_the_index_forward_is_refused() {
        for suite in Suite::STRENGTH {
            let (mut protector, mut unprotector) = pair(Policy::new(suite));
            let first = sent(&mut protector, 10);
            for again in [10, 9, 10_u16.wrapping_add(0x8000)] {
                let plain = packet(again, b"payload");
                let mut buffer = room(&plain, protector.rtp_overhead());
                assert_eq!(
                    protector.protect_rtp(&mut buffer, plain.len()),
                    Err(SrtpError::IndexNotAdvancing),
                    "{suite:?}, sequence {again}"
                );
            }
            assert_eq!(protector.rollover(), 0, "{suite:?}");
            // nothing refused moved the index: the next number still follows
            let mut next = sent(&mut protector, 11);
            assert!(unprotector.unprotect_rtp(&mut first.clone()).is_ok());
            assert!(unprotector.unprotect_rtp(&mut next).is_ok(), "{suite:?}");
        }
    }

    #[test]
    fn a_master_key_or_salt_of_the_wrong_width_keys_nothing() {
        for suite in Suite::STRENGTH {
            let (key, salt) = (suite.key_len(), suite.salt_len());
            assert!(master_for(suite).fits(suite), "{suite:?}");
            for (key, salt) in [
                (key - 1, salt),
                (key + 1, salt),
                (5, salt),
                (key, salt - 1),
                (key, salt + 2),
            ] {
                let wrong = || Master::new(&vec![0x11; key], &vec![0x22; salt]);
                assert!(!wrong().fits(suite), "{suite:?} {key}/{salt}");
                let policy = Policy::new(suite);
                let mut protector = Protector::new(policy, wrong());
                let plain = packet(1, b"payload");
                let mut buffer = room(&plain, protector.rtp_overhead());
                assert_eq!(
                    protector.protect_rtp(&mut buffer, plain.len()),
                    Err(SrtpError::KeyLength),
                    "{suite:?} {key}/{salt}"
                );
                assert_eq!(buffer.get(..plain.len()), plain.get(..));
                let report = compound();
                let mut buffer = room(&report, protector.rtcp_overhead());
                assert_eq!(
                    protector.protect_rtcp(&mut buffer, report.len()),
                    Err(SrtpError::KeyLength)
                );

                let mut unprotector = Unprotector::new(policy, wrong());
                let mut good = sent(&mut Protector::new(policy, master_for(suite)), 1);
                assert_eq!(
                    unprotector.unprotect_rtp(&mut good),
                    Err(SrtpError::KeyLength)
                );
                let (mut good, _) = reported(&mut Protector::new(policy, master_for(suite)), SSRC);
                assert_eq!(
                    unprotector.unprotect_rtcp(&mut good),
                    Err(SrtpError::KeyLength)
                );
            }
        }
    }

    // RFC 4568 §6.1: a key declared with `|2^4` protects, and opens, fewer
    // than sixteen SRTP packets and fewer than sixteen SRTCP packets; the
    // sixteenth of each is refused in both directions, and nothing about it
    // moves the context
    #[test]
    fn a_declared_lifetime_is_held_to_in_both_directions() {
        for suite in [Suite::AesCm80, Suite::AeadAes256Gcm] {
            let bounded = Policy {
                lifetime: Some(16),
                ..Policy::new(suite)
            };
            let mut protector = Protector::new(bounded, master_for(suite));
            let mut unbounded = Protector::new(Policy::new(suite), master_for(suite));
            let mut unprotector = Unprotector::new(bounded, master_for(suite));
            for sequence in 1..16 {
                let _ = sent(&mut protector, sequence);
                let mut arriving = sent(&mut unbounded, sequence);
                assert!(
                    unprotector.unprotect_rtp(&mut arriving).is_ok(),
                    "{suite:?}"
                );
                let _ = reported(&mut protector, SSRC);
                let (mut report, _) = reported(&mut unbounded, SSRC);
                assert!(unprotector.unprotect_rtcp(&mut report).is_ok(), "{suite:?}");
            }
            let plain = packet(16, b"payload");
            let mut buffer = room(&plain, protector.rtp_overhead());
            assert_eq!(
                protector.protect_rtp(&mut buffer, plain.len()),
                Err(SrtpError::KeyExhausted),
                "{suite:?}"
            );
            let report = compound();
            let mut buffer = room(&report, protector.rtcp_overhead());
            assert_eq!(
                protector.protect_rtcp(&mut buffer, report.len()),
                Err(SrtpError::KeyExhausted),
                "{suite:?}"
            );
            let mut arriving = sent(&mut unbounded, 16);
            assert_eq!(
                unprotector.unprotect_rtp(&mut arriving),
                Err(SrtpError::KeyExhausted),
                "{suite:?}"
            );
            let (mut report, _) = reported(&mut unbounded, SSRC);
            assert_eq!(
                unprotector.unprotect_rtcp(&mut report),
                Err(SrtpError::KeyExhausted),
                "{suite:?}"
            );
        }
    }

    // §3.4: the SRTCP index is never reset under one key, and §9.1 holds the
    // SRTP index to the same: a caller that names the key in use as a new
    // one has not re-keyed anything
    #[test]
    fn the_key_in_use_named_as_a_new_one_carries_every_index_on() {
        let policy = Policy::new(Suite::AesCm80);
        let mut security = Security::new(policy, master(), policy, master());
        issued(&mut security, 100);
        for _ in 0..3 {
            let plain = compound();
            let mut buffer = room(&plain, security.rtcp_overhead());
            security
                .protect_rtcp(&mut buffer, plain.len())
                .expect("the report protects");
        }

        security.rekey_local(policy, master(), Rekeyed::Key);
        let plain = packet(100, b"payload");
        let mut buffer = room(&plain, security.rtp_overhead());
        assert_eq!(
            security.protect_rtp(&mut buffer, plain.len()),
            Err(SrtpError::IndexNotAdvancing),
            "the packet index started again under the key it had spent"
        );
        let (_, index) = reported(&mut security.sending, SSRC);
        assert_eq!(index, 3, "the SRTCP index started again under its key");

        // and the receiving side keeps its replay lists
        let mut far = Protector::new(policy, master());
        let wire = sent(&mut far, 5);
        let (report, _) = reported(&mut far, SSRC);
        assert!(security.unprotect_rtp(&mut wire.clone()).is_ok());
        assert!(security.unprotect_rtcp(&mut report.clone()).is_ok());
        security.rekey_remote(policy, master(), Rekeyed::Key);
        assert_eq!(
            security.unprotect_rtp(&mut wire.clone()),
            Err(SrtpError::Replayed)
        );
        assert_eq!(
            security.unprotect_rtcp(&mut report.clone()),
            Err(SrtpError::Replayed)
        );

        // a key that is new really does start again
        security.rekey_local(policy, other_master(), Rekeyed::Key);
        let (_, index) = reported(&mut security.sending, SSRC);
        assert_eq!(index, 0);
    }

    // `Security`'s retired context is tried on the very datagram the current
    // one refused, which is sound only if a refusal leaves it as it arrived:
    // held here for every suite, for the tag check of the MAC suites and for
    // the GCM open of the AEAD ones, on both protocols
    #[test]
    fn a_packet_that_does_not_open_is_left_as_it_arrived() {
        for suite in Suite::STRENGTH {
            let policy = Policy::new(suite);
            let mut protector = Protector::new(policy, master_for(suite));
            let other = Master::new(&vec![0x55; suite.key_len()], &vec![0x22; suite.salt_len()]);
            let mut stranger = Unprotector::new(policy, other);

            let wire = sent(&mut protector, 9);
            let mut tried = wire.clone();
            assert_eq!(
                stranger.unprotect_rtp(&mut tried),
                Err(SrtpError::NotAuthentic),
                "{suite:?}"
            );
            assert_eq!(tried, wire, "{suite:?}");

            let (report, _) = reported(&mut protector, SSRC);
            let mut tried = report.clone();
            assert_eq!(
                stranger.unprotect_rtcp(&mut tried),
                Err(SrtpError::NotAuthentic),
                "{suite:?}"
            );
            assert_eq!(tried, report, "{suite:?}");
        }
    }

    #[test]
    fn a_peer_still_on_its_old_key_is_heard_under_every_suite() {
        for suite in Suite::STRENGTH {
            let policy = Policy::new(suite);
            let other = || Master::new(&vec![0x55; suite.key_len()], &vec![0x66; suite.salt_len()]);
            let mut before = Protector::new(policy, master_for(suite));
            let mut security = Security::new(policy, master_for(suite), policy, master_for(suite));
            security.rekey_remote(policy, other(), Rekeyed::Key);
            let mut crossing = sent(&mut before, 100);
            assert_eq!(
                security.unprotect_rtp(&mut crossing).map(|_| ()),
                Ok(()),
                "{suite:?}"
            );
            let (mut report, _) = reported(&mut before, SSRC);
            assert_eq!(
                security.unprotect_rtcp(&mut report).map(|_| ()),
                Ok(()),
                "{suite:?}"
            );
        }
    }

    // a source that gave way to others keeps its replay list's floor and its
    // rollover counter: heard from again, a recording of it is still old
    #[test]
    fn a_source_that_gave_way_is_held_to_where_it_had_got() {
        let policy = Policy::new(Suite::AesCm80);
        let mut talking = Protector::new(policy, master());
        let mut unprotector = Unprotector::new(policy, master());

        let mut recorded = Vec::new();
        let mut sequence = 65_533_u16;
        for _ in 0..5 {
            let datagram = sent_from(&mut talking, SSRC, sequence);
            assert!(unprotector.unprotect_rtp(&mut datagram.clone()).is_ok());
            recorded.push(datagram);
            sequence = sequence.wrapping_add(1);
        }
        let (report, _) = reported(&mut talking, SSRC);
        assert!(unprotector.unprotect_rtcp(&mut report.clone()).is_ok());

        // as many other sources as the table holds push it out
        for source in 1..=u32::try_from(SOURCES).unwrap_or(u32::MAX) {
            let mut other = Protector::new(policy, master());
            let mut datagram = sent_from(&mut other, source, 10);
            assert!(unprotector.unprotect_rtp(&mut datagram).is_ok());
            let (mut report, _) = reported(&mut other, source);
            assert!(unprotector.unprotect_rtcp(&mut report).is_ok());
        }
        assert!(unprotector.rtp.get(SSRC).is_none(), "the source gave way");
        assert!(unprotector.rtcp.get(SSRC).is_none());

        for datagram in &recorded {
            assert_eq!(
                unprotector.unprotect_rtp(&mut datagram.clone()),
                Err(SrtpError::Replayed)
            );
        }
        assert_eq!(
            unprotector.unprotect_rtcp(&mut report.clone()),
            Err(SrtpError::Replayed)
        );

        // and what it sends next, past its wrap, still opens
        let mut next = sent_from(&mut talking, SSRC, sequence);
        assert_eq!(unprotector.unprotect_rtp(&mut next).map(|_| ()), Ok(()));
        let (mut report, _) = reported(&mut talking, SSRC);
        assert_eq!(unprotector.unprotect_rtcp(&mut report).map(|_| ()), Ok(()));
    }

    #[test]
    fn the_record_of_sources_that_gave_way_is_bounded() {
        let mut forgotten = super::Forgotten::new();
        for ssrc in 0..u32::try_from(super::FORGOTTEN * 2).unwrap_or(u32::MAX) {
            forgotten.note(ssrc, u64::from(ssrc));
        }
        assert_eq!(forgotten.get(0), None, "the oldest went first");
        let last = u32::try_from(super::FORGOTTEN * 2 - 1).unwrap_or(u32::MAX);
        assert_eq!(forgotten.get(last), Some(u64::from(last)));
        forgotten.note(last, 7);
        assert_eq!(forgotten.get(last), Some(7), "one entry per source");
    }

    // with a key derivation rate, an arriving index in another phase is
    // derived for, but the derivation is kept only once the packet has
    // authenticated: a forged one leaves the keys of the running stream
    #[test]
    fn a_forged_packet_in_another_phase_leaves_the_session_keys_in_place() {
        for suite in [Suite::AesCm80, Suite::AeadAes128Gcm] {
            let mut policy = Policy::new(suite);
            policy.rate = Rate::from_exponent(4).expect("in range");
            let (mut protector, mut unprotector) = pair(policy);
            let mut datagram = sent(&mut protector, 3);
            assert!(unprotector.unprotect_rtp(&mut datagram).is_ok());
            let (mut report, _) = reported(&mut protector, SSRC);
            assert!(unprotector.unprotect_rtcp(&mut report).is_ok());

            // a packet numbered into the next phase, its tag corrupted
            let mut forged = sent(&mut protector, 40);
            if let Some(last) = forged.last_mut() {
                *last ^= 1;
            }
            assert_eq!(
                unprotector.unprotect_rtp(&mut forged),
                Err(SrtpError::NotAuthentic)
            );
            let current = unprotector.keys.current().expect("keyed");
            assert_eq!(current.rtp_phase, 0, "{suite:?}");

            // a genuine one in that phase moves them
            let mut genuine = sent(&mut protector, 41);
            assert!(unprotector.unprotect_rtp(&mut genuine).is_ok());
            let current = unprotector.keys.current().expect("keyed");
            assert_eq!(current.rtp_phase, 41 >> 4, "{suite:?}");
            assert_eq!(current.rtcp_phase, 0, "{suite:?}");
        }
    }

    // what wipes each session key when it goes is its type, since the wipe
    // itself cannot be watched from safe code: held here, so that a change to
    // a plain copy does not compile
    #[test]
    fn the_session_keys_are_held_in_buffers_that_wipe_themselves() {
        let (protector, _) = pair(Policy::new(Suite::AesCm80));
        let current = protector.keys.current().expect("keyed");
        let _: &Zeroizing<Vec<u8>> = &current.rtp.salt;
        let super::Cipher::Mac { authentication, .. } = &current.rtcp.cipher else {
            panic!("a MAC suite");
        };
        let _: &Zeroizing<[u8; super::kdf::AUTH]> = authentication;
    }
}
