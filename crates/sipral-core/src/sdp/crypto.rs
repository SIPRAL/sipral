// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What an `a=crypto` line actually says, read out of the text (RFC 4568).
//!
//! [`Crypto`](super::Crypto) keeps the line as it arrived, because a
//! description that is read and written back has to come out as it went in.
//! This is the other half: the suite as a value rather than a token, and the
//! key parameter decoded into the master key and salt SRTP wants, with the
//! lifetime and the master key identifier that travel beside them.
//!
//! Nothing here encrypts anything. `sipral-core` opens no sockets and knows
//! no transforms; it reads the offer and says what was agreed, and the crate
//! that owns the media does the rest.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};

/// Master key length, which is 128 bits for every suite RFC 4568 itself
/// defines. RFC 6188's and RFC 7714's suites carry a wider one; a caller that
/// cares which suite it is reads [`CryptoSuite::key_len`] instead.
pub const MASTER_KEY: usize = 16;

/// Master salt length: 112 bits, for the same suites `MASTER_KEY` is exact
/// for. RFC 7714's two AEAD suites use a 96-bit one; see
/// [`CryptoSuite::salt_len`].
pub const MASTER_SALT: usize = 14;

/// §6.2: the master key lifetime in SRTP packets.
const SRTP_LIFETIME: u64 = 1 << 48;

/// §6.2: and in SRTCP packets, which is the one that runs out first.
const SRTCP_LIFETIME: u64 = 1 << 31;

/// The transforms this stack implements: RFC 4568 §6.2's three, RFC 6188's
/// two wider `AES_CM` suites, and RFC 7714's two AEAD ones.
///
/// The names are the tokens on the wire. The formal grammar in RFC 4568
/// §9.2 prints `F8_128_HMAC_SHA1_32`, which no section defines and which
/// erratum 6808 corrects to `F8_128_HMAC_SHA1_80`; §6.2.3 and the IANA
/// registration both say 80, so that is what this reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoSuite {
    /// `AES_CM_128_HMAC_SHA1_80`, the default.
    AesCm80,
    /// `AES_CM_128_HMAC_SHA1_32`, the same with a shorter tag on SRTP —
    /// SRTCP's stays at eighty bits.
    AesCm32,
    /// `F8_128_HMAC_SHA1_80`.
    AesF8,
    /// `AES_256_CM_HMAC_SHA1_80` (RFC 6188): `AesCm80` with a 256-bit key.
    Aes256Cm80,
    /// `AES_256_CM_HMAC_SHA1_32` (RFC 6188): `AesCm32` with a 256-bit key.
    Aes256Cm32,
    /// `AEAD_AES_128_GCM` (RFC 7714 §14.1).
    AeadAes128Gcm,
    /// `AEAD_AES_256_GCM` (RFC 7714 §14.1).
    AeadAes256Gcm,
}

impl CryptoSuite {
    /// Every suite this stack implements, strongest first: the order an
    /// offer names them in, and the order an answerer would pick among a
    /// peer's own offer if RFC 4568 let it (§5.1.2 does not -- see
    /// `sipral::keying::acceptable`, which keeps to the offerer's order for
    /// that reason).
    pub const STRENGTH: [Self; 7] = [
        Self::AeadAes256Gcm,
        Self::AeadAes128Gcm,
        Self::Aes256Cm80,
        Self::AesCm80,
        Self::AesF8,
        Self::Aes256Cm32,
        Self::AesCm32,
    ];

    /// Whether this suite ties confidentiality and integrity into one AEAD
    /// transform.
    #[must_use]
    pub const fn is_aead(self) -> bool {
        matches!(self, Self::AeadAes128Gcm | Self::AeadAes256Gcm)
    }

    /// The master key length this suite's `inline:` parameter carries.
    #[must_use]
    pub const fn key_len(self) -> usize {
        match self {
            Self::AesCm80 | Self::AesCm32 | Self::AesF8 | Self::AeadAes128Gcm => MASTER_KEY,
            Self::Aes256Cm80 | Self::Aes256Cm32 | Self::AeadAes256Gcm => 32,
        }
    }

    /// The master salt length: RFC 7714 §8.1's twelve octets for the AEAD
    /// suites, RFC 3711 §5.1's fourteen for the rest.
    #[must_use]
    pub const fn salt_len(self) -> usize {
        if self.is_aead() { 12 } else { MASTER_SALT }
    }

    /// §6.2.1: "The length of the base64-decoded key and salt value for this
    /// crypto-suite MUST be" this many characters, and §6.2.2, §6.2.3 and RFC
    /// 6188/7714's own registrations repeat it for their own suites.
    #[must_use]
    pub const fn key_salt_len(self) -> usize {
        self.key_len() + self.salt_len()
    }

    /// The token this suite carries in the line.
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

    /// The suite a token names, if it is one this stack implements.
    ///
    /// §4: "The values of each of these fields is case-insensitive."
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::STRENGTH
            .into_iter()
            .find(|suite| suite.name().eq_ignore_ascii_case(name))
    }

    /// The largest lifetime a key may declare: the smaller of the two limits
    /// in §6.2, since one master key covers both streams. The same for every
    /// suite -- RFC 6188 and RFC 7714 do not move it.
    #[must_use]
    pub const fn max_lifetime(self) -> u64 {
        if SRTP_LIFETIME < SRTCP_LIFETIME {
            SRTP_LIFETIME
        } else {
            SRTCP_LIFETIME
        }
    }
}

/// A master key and salt, and the promise not to print them.
///
/// No `Debug` and no way to read the bytes except by asking: a value that
/// cannot be printed cannot be printed by accident. Overwritten on drop, best
/// effort and said so plainly, exactly as `Secret` is — a volatile write needs
/// `unsafe`, which this crate denies.
///
/// The key and salt are stored one after the other rather than as two
/// separate buffers, and `key_len` is where the join is — every suite this
/// stack implements has a key at least as wide as its salt, so nothing here
/// needs to store both lengths. Grown rather than fixed, because RFC 6188 and
/// RFC 7714 add suites whose key and salt are not RFC 4568's original
/// sixteen and fourteen octets.
#[derive(Clone)]
pub struct KeySalt {
    bytes: Vec<u8>,
    key_len: usize,
}

/// Every octet compared, whatever the first difference: two keys are
/// compared where one of them came from the far end (an answer's key held to
/// the offer's, a re-offer's to the key in force), and a comparison that
/// stopped at the first difference would time how much of a guess was
/// right. The widths are not secret, and differing widths answer at once.
impl PartialEq for KeySalt {
    fn eq(&self, other: &Self) -> bool {
        if self.key_len != other.key_len || self.bytes.len() != other.bytes.len() {
            return false;
        }
        let differ = self
            .bytes
            .iter()
            .zip(&other.bytes)
            .fold(0_u8, |seen, (one, two)| seen | (one ^ two));
        core::hint::black_box(differ) == 0
    }
}

impl Eq for KeySalt {}

impl KeySalt {
    /// The concatenation a key management protocol produced.
    #[must_use]
    pub fn new(key: &[u8], salt: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(key.len() + salt.len());
        bytes.extend_from_slice(key);
        bytes.extend_from_slice(salt);
        Self {
            bytes,
            key_len: key.len(),
        }
    }

    /// The master key.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        self.bytes.get(..self.key_len).unwrap_or_default()
    }

    /// The master salt.
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        self.bytes.get(self.key_len..).unwrap_or_default()
    }
}

impl Drop for KeySalt {
    fn drop(&mut self) {
        self.bytes.fill(0);
        compiler_fence(Ordering::SeqCst);
    }
}

impl fmt::Debug for KeySalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KeySalt(<redacted>)")
    }
}

/// A master key identifier and the width of the field it occupies in every
/// packet (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyIdentifier {
    /// "a positive decimal integer that is encoded as a big-endian integer in
    /// the actual SRTP packets".
    pub value: u128,
    /// "the size of the MKI field in the SRTP packet, specified in bytes".
    pub length: u8,
}

/// One `inline:` key parameter, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inline {
    /// The master key and salt.
    pub keys: KeySalt,
    /// "master key lifetime (max number of SRTP or SRTCP packets using this
    /// master key)", absent when the suite's default applies.
    pub lifetime: Option<u64>,
    /// The identifier, when the peer asked for one.
    pub mki: Option<KeyIdentifier>,
}

impl Inline {
    /// A key parameter with no lifetime and no identifier, which is what an
    /// offer carries unless there is a reason for more.
    #[must_use]
    pub const fn new(keys: KeySalt) -> Self {
        Self {
            keys,
            lifetime: None,
            mki: None,
        }
    }

    /// The text this goes back on the wire as, `inline:` included.
    #[must_use]
    pub fn to_value(&self) -> String {
        let mut out = String::from("inline:");
        out.push_str(&base64_encode(&self.keys.bytes));
        if let Some(lifetime) = self.lifetime {
            out.push('|');
            // the power-of-two form when it is one, since that is what the
            // examples in §6.1 use and it is shorter
            if lifetime.is_power_of_two() {
                out.push_str("2^");
                out.push_str(&lifetime.trailing_zeros().to_string());
            } else {
                out.push_str(&lifetime.to_string());
            }
        }
        if let Some(mki) = self.mki {
            out.push('|');
            out.push_str(&mki.value.to_string());
            out.push(':');
            out.push_str(&mki.length.to_string());
        }
        out
    }

    /// Read one key parameter for `suite`.
    ///
    /// Every rule here is one the RFC states as making the whole crypto
    /// attribute invalid: a decoded length that is not the suite's, a
    /// lifetime past the suite's maximum, an identifier without a length or
    /// with one above 128.
    fn parse(text: &str, suite: CryptoSuite) -> Option<Self> {
        let rest = strip_prefix_ignore_case(text, "inline:")?;
        let mut fields = rest.split('|');

        // dropped, it is wiped: a key of the wrong width is as secret as one
        // of the right width
        let decoded = base64_decode(fields.next()?)?;
        if decoded.len() != suite.key_salt_len() {
            return None;
        }
        let keys = KeySalt {
            key_len: suite.key_len(),
            bytes: decoded.take(),
        };

        // §6.1: "the lifetime field never includes a colon, whereas the third
        // field always does", which is how the two optional fields are told
        // apart when only one is present
        let mut lifetime = None;
        let mut mki = None;
        for field in fields {
            if field.contains(':') {
                if mki.is_some() {
                    return None;
                }
                mki = Some(parse_mki(field)?);
            } else {
                if lifetime.is_some() || mki.is_some() {
                    return None;
                }
                let value = parse_lifetime(field)?;
                if value > suite.max_lifetime() {
                    return None;
                }
                lifetime = Some(value);
            }
        }

        Some(Self {
            keys,
            lifetime,
            mki,
        })
    }
}

/// The session parameters of §6.3, as far as they change what SRTP does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionParams {
    /// `UNENCRYPTED_SRTP`: send and expect RTP payloads in the clear.
    pub unencrypted_rtp: bool,
    /// `UNENCRYPTED_SRTCP`: the same for RTCP. §6.3.2 adds that the SRTCP E
    /// bit "MUST be clear (0) in all SRTCP messages" when this is signalled,
    /// and MUST be set otherwise.
    pub unencrypted_rtcp: bool,
    /// `UNAUTHENTICATED_SRTP`: no tag on RTP. Never on RTCP, whose tag RFC
    /// 3711 §3.4 makes required.
    pub unauthenticated_rtp: bool,
    /// `KDR=n`, the key derivation rate as the exponent of two. Absent means
    /// a single derivation (§6.3.1).
    pub kdr: Option<u8>,
    /// `WSH=n`, the replay window the peer suggests. §6.3.6 makes it a hint,
    /// and its minimum is 64.
    pub window: Option<u32>,
}

impl SessionParams {
    /// What §6.3 says applies when nothing is signalled: everything
    /// encrypted, everything authenticated, one derivation.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            unencrypted_rtp: false,
            unencrypted_rtcp: false,
            unauthenticated_rtp: false,
            kdr: None,
            window: None,
        }
    }

    /// Read the session parameters of a crypto line.
    ///
    /// `None` for a line this stack cannot be held to. §6.3.7 is the opposite
    /// of the usual extension rule and is worth quoting, because reading it
    /// the usual way produces a stack that silently ignores what a peer
    /// required: "New SRTP session parameters are by default mandatory. A
    /// newly defined SRTP session parameter that is prefixed with the dash
    /// character ('-'), however, is considered optional and MAY be ignored.
    /// If an SDP crypto attribute is received with an unknown session
    /// parameter that is not prefixed with a '-' character, that crypto
    /// attribute MUST be considered invalid."
    ///
    /// So an unknown parameter is fatal to the line unless it opted out of
    /// being. A line that is invalid is one that cannot be accepted, and
    /// §7.1.2 has an answerer that can accept none refuse the stream rather
    /// than fall back to something weaker.
    #[must_use]
    pub fn parse(parameters: &[String]) -> Option<Self> {
        let mut params = Self::new();
        for parameter in parameters {
            let text = parameter.as_str();
            if text.starts_with('-') {
                // said to be safe to ignore by whoever defined it
                continue;
            }
            if text.eq_ignore_ascii_case("UNENCRYPTED_SRTP") {
                params.unencrypted_rtp = true;
            } else if text.eq_ignore_ascii_case("UNENCRYPTED_SRTCP") {
                params.unencrypted_rtcp = true;
            } else if text.eq_ignore_ascii_case("UNAUTHENTICATED_SRTP") {
                params.unauthenticated_rtp = true;
            } else if let Some(value) = strip_prefix_ignore_case(text, "KDR=") {
                let rate: u8 = value.parse().ok()?;
                if rate > 24 {
                    return None;
                }
                params.kdr = Some(rate);
            } else if let Some(value) = strip_prefix_ignore_case(text, "WSH=") {
                let window: u32 = value.parse().ok()?;
                if window < 64 {
                    return None;
                }
                params.window = Some(window);
            } else {
                return None;
            }
        }
        Some(params)
    }

    /// The parameters as they go on the line, in the order §9.2 lists them.
    #[must_use]
    pub fn to_values(self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(rate) = self.kdr {
            out.push(format!("KDR={rate}"));
        }
        if self.unencrypted_rtp {
            out.push("UNENCRYPTED_SRTP".to_owned());
        }
        if self.unencrypted_rtcp {
            out.push("UNENCRYPTED_SRTCP".to_owned());
        }
        if self.unauthenticated_rtp {
            out.push("UNAUTHENTICATED_SRTP".to_owned());
        }
        if let Some(window) = self.window {
            out.push(format!("WSH={window}"));
        }
        out
    }
}

impl Default for SessionParams {
    fn default() -> Self {
        Self::new()
    }
}

/// An `a=crypto` line read as values rather than as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoPolicy {
    /// The tag, which is how an answer says which offered line it took.
    pub tag: u32,
    /// The transform.
    pub suite: CryptoSuite,
    /// The keys, in the order they were offered. §6.1 allows more than one
    /// when they carry identifiers to tell them apart.
    pub keys: Vec<Inline>,
    /// What else the line asked for.
    pub params: SessionParams,
}

impl super::Crypto {
    /// Read this line as values.
    ///
    /// `None` where the RFC says the crypto attribute "MUST be considered
    /// invalid": an unknown suite, a key that is not the suite's length, a
    /// lifetime past its maximum, a malformed identifier. A line that cannot
    /// be read is one that cannot be accepted, and §7.1.2 says an answerer
    /// that accepts none refuses the stream rather than falling back.
    #[must_use]
    pub fn policy(&self) -> Option<CryptoPolicy> {
        let suite = CryptoSuite::from_name(&self.suite)?;
        let keys: Option<Vec<Inline>> = self
            .key_params
            .split(';')
            .map(|param| Inline::parse(param, suite))
            .collect();
        let keys = keys?;
        if keys.is_empty() {
            return None;
        }
        // §6.1: every master key "MUST be unique ... with respect to other
        // master keys in the entire SDP message", and more than one on a line
        // is only meaningful when each carries an identifier
        if keys.len() > 1 && keys.iter().any(|key| key.mki.is_none()) {
            return None;
        }
        Some(CryptoPolicy {
            tag: self.tag,
            suite,
            keys,
            params: SessionParams::parse(&self.session_params)?,
        })
    }
}

impl CryptoPolicy {
    /// The line this policy writes.
    #[must_use]
    pub fn to_crypto(&self) -> super::Crypto {
        let key_params = self
            .keys
            .iter()
            .map(Inline::to_value)
            .collect::<Vec<_>>()
            .join(";");
        super::Crypto {
            tag: self.tag,
            suite: self.suite.name().to_owned(),
            key_params,
            session_params: self.params.to_values(),
        }
    }

    /// One offered line with one key and nothing else said.
    #[must_use]
    pub fn new(tag: u32, suite: CryptoSuite, keys: KeySalt) -> Self {
        Self {
            tag,
            suite,
            keys: vec![Inline::new(keys)],
            params: SessionParams::new(),
        }
    }
}

/// §6.1: "MKI:length", with the length in bytes and at most 128.
fn parse_mki(field: &str) -> Option<KeyIdentifier> {
    let (value, length) = field.split_once(':')?;
    if leading_zero(value) || leading_zero(length) {
        return None;
    }
    let length: u32 = length.parse().ok()?;
    if !(1..=128).contains(&length) {
        return None;
    }
    Some(KeyIdentifier {
        value: value.parse().ok()?,
        // a value wider than sixteen octets has nowhere to come from, since
        // the number itself is parsed as one
        length: u8::try_from(length).ok()?,
    })
}

/// §6.1: a decimal integer, or the literal `2^` and an exponent.
fn parse_lifetime(field: &str) -> Option<u64> {
    if let Some(exponent) = field.strip_prefix("2^") {
        if leading_zero(exponent) {
            return None;
        }
        let exponent: u32 = exponent.parse().ok()?;
        return (exponent < 64).then(|| 1_u64 << exponent);
    }
    if leading_zero(field) {
        return None;
    }
    let value: u64 = field.parse().ok()?;
    (value > 0).then_some(value)
}

/// "leading zeroes MUST NOT be used", which the RFC says of the tag, the
/// lifetime, the identifier and its length alike.
///
/// `pub(super)` because [`Crypto`](super::plan::Crypto) owns the one of those
/// four fields that lives outside this module and has to check it the same
/// way.
pub(super) fn leading_zero(text: &str) -> bool {
    text.len() > 1 && text.starts_with('0')
}

fn strip_prefix_ignore_case<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    let head = text.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| text.get(prefix.len()..))
        .flatten()
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 as RFC 4648 §4 defines it, which is what RFC 3548 was.
fn base64_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = *chunk.first().unwrap_or(&0);
        let b = *chunk.get(1).unwrap_or(&0);
        let c = *chunk.get(2).unwrap_or(&0);
        let word = u32::from(a) << 16 | u32::from(b) << 8 | u32::from(c);
        for shift in [18, 12, 6, 0] {
            let index = usize::try_from((word >> shift) & 0x3f).unwrap_or(0);
            out.push(char::from(*ALPHABET.get(index).unwrap_or(&b'A')));
        }
        // one padding character for every octet the chunk was short, and the
        // characters come off before any go on
        let short = 3 - chunk.len();
        out.truncate(out.len() - short);
        for _ in 0..short {
            out.push('=');
        }
    }
    out
}

/// The inverse. §6.1: "padding characters ... at the end of the base64-encoded
/// data are discarded", so trailing `=` is accepted and so is its absence;
/// anything else outside the alphabet is not.
fn base64_decode(text: &str) -> Option<Decoded> {
    let body = text.trim_end_matches('=');
    if body.len() % 4 == 1 {
        return None;
    }
    // every character carries six bits, so this is the exact count of whole
    // octets: the buffer never grows, and never leaves a copy behind growing
    let mut out = Decoded(Vec::with_capacity(body.len() * 3 / 4));
    let mut word = 0_u32;
    let mut bits = 0_u32;
    for byte in body.bytes() {
        let value = ALPHABET.iter().position(|c| *c == byte)?;
        word = word << 6 | u32::try_from(value).ok()?;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.0.push(u8::try_from((word >> bits) & 0xff).unwrap_or(0));
        }
    }
    // whatever is left over has to be zero, or the encoding named bits that
    // no octet carries
    (word & ((1 << bits) - 1) == 0).then_some(out)
}

/// Decoded key material on its way into a [`KeySalt`]: overwritten when it
/// is dropped, so a decode that fails part way, or a key of the wrong width,
/// leaves nothing of itself behind. Best effort, as [`KeySalt`] is.
struct Decoded(Vec<u8>);

impl Decoded {
    /// The bytes, handed on to whatever wipes them next.
    fn take(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

impl core::ops::Deref for Decoded {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Decoded {
    fn drop(&mut self) {
        self.0.fill(0);
        compiler_fence(Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CryptoPolicy, CryptoSuite, Inline, KeyIdentifier, KeySalt, MASTER_KEY, MASTER_SALT,
        SessionParams, base64_decode, base64_encode,
    };
    use crate::sdp::Crypto;

    fn line(value: &str) -> Crypto {
        Crypto::parse(value).expect("a well-formed line")
    }

    // RFC 4648 §10
    #[test]
    fn the_published_base64_vectors() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64_encode(plain.as_bytes()), encoded, "{plain}");
            assert_eq!(
                base64_decode(encoded).as_deref(),
                Some(plain.as_bytes()),
                "{encoded}"
            );
        }
    }

    #[test]
    fn base64_without_padding_reads_the_same() {
        assert_eq!(
            base64_decode("Zm8").as_deref(),
            base64_decode("Zm8=").as_deref()
        );
        assert_eq!(
            base64_decode("Zg").as_deref(),
            base64_decode("Zg==").as_deref()
        );
    }

    /// D7: equality reads every octet and still answers right: equal keys,
    /// a first octet that differs, a last one that differs, and two keys of
    /// different widths. The decode of a key is held in a buffer sized once,
    /// so it never grows and leaves a copy of itself behind.
    #[test]
    fn keys_are_equal_by_every_octet_and_decoded_without_growing() {
        let key = KeySalt::new(&[7; 16], &[9; 14]);
        assert_eq!(key, KeySalt::new(&[7; 16], &[9; 14]));
        let mut first = [7; 16];
        first[0] = 8;
        assert_ne!(key, KeySalt::new(&first, &[9; 14]));
        let mut last = [9; 14];
        last[13] = 8;
        assert_ne!(key, KeySalt::new(&[7; 16], &last));
        assert_ne!(key, KeySalt::new(&[7; 16], &[9; 12]));
        assert_ne!(key, KeySalt::new(&[7; 14], &[9; 16]));
        for len in [30_usize, 44, 46] {
            let encoded = base64_encode(&vec![0x5a; len]);
            let decoded = base64_decode(&encoded).expect("a key");
            assert_eq!(decoded.len(), len);
            assert_eq!(decoded.0.capacity(), len, "the buffer grew: {len}");
        }
    }

    #[test]
    fn base64_refuses_what_is_not_base64() {
        assert!(base64_decode("Zm8*").is_none());
        assert!(
            base64_decode("Z").is_none(),
            "a lone character names no octet"
        );
        assert!(base64_decode("Zm9=").is_none(), "bits nothing carries");
    }

    #[test]
    fn every_byte_survives_the_round_trip() {
        let all: Vec<u8> = (0..=255).collect();
        for len in 0..=all.len() {
            let bytes = all.get(..len).unwrap_or_default();
            let encoded = base64_encode(bytes);
            assert_eq!(base64_decode(&encoded).as_deref(), Some(bytes), "{len}");
        }
    }

    // the example in RFC 4568 §4
    #[test]
    fn the_examples_from_the_rfc() {
        let crypto = line(
            "1 AES_CM_128_HMAC_SHA1_80 \
             inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32",
        );
        let policy = crypto.policy().expect("valid");
        assert_eq!(policy.tag, 1);
        assert_eq!(policy.suite, CryptoSuite::AesCm80);
        let key = policy.keys.first().expect("one key");
        assert_eq!(key.lifetime, Some(1 << 20));
        assert_eq!(
            key.mki,
            Some(KeyIdentifier {
                value: 1,
                length: 32
            })
        );
        assert_eq!(policy.to_crypto().to_value(), crypto.to_value());
    }

    #[test]
    fn the_second_example_has_an_identifier_and_no_lifetime() {
        let crypto = line(
            "1 AES_CM_128_HMAC_SHA1_80 \
             inline:YUJDZGVmZ2hpSktMbW9QUXJzVHVWd3l6MTIzNDU2|1066:4",
        );
        let policy = crypto.policy().expect("valid");
        let key = policy.keys.first().expect("one key");
        assert_eq!(key.lifetime, None);
        assert_eq!(
            key.mki,
            Some(KeyIdentifier {
                value: 1066,
                length: 4
            })
        );
        assert_eq!(key.keys.key().len() + key.keys.salt().len(), 30);
    }

    // §6.1: "the lifetime field never includes a colon, whereas the third
    // field always does". So a bare "|1" is a lifetime of one packet, not an
    // identifier missing its length — there is nothing to refuse
    #[test]
    fn a_bare_number_is_a_lifetime() {
        let keys = base64_encode(&[0x41; 30]);
        let policy = line(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{keys}|1"))
            .policy()
            .expect("valid");
        let key = policy.keys.first().expect("one key");
        assert_eq!(key.lifetime, Some(1));
        assert_eq!(key.mki, None);
    }

    #[test]
    fn a_lifetime_alone_is_told_from_an_identifier_alone() {
        let with_lifetime = line(
            "1 AES_CM_128_HMAC_SHA1_80 \
             inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20",
        )
        .policy()
        .expect("valid");
        let key = with_lifetime.keys.first().expect("one key");
        assert_eq!(key.lifetime, Some(1 << 20));
        assert_eq!(key.mki, None);

        let with_mki = line(
            "1 AES_CM_128_HMAC_SHA1_80 \
             inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|7:1",
        )
        .policy()
        .expect("valid");
        let key = with_mki.keys.first().expect("one key");
        assert_eq!(key.lifetime, None);
        assert_eq!(
            key.mki,
            Some(KeyIdentifier {
                value: 7,
                length: 1
            })
        );
    }

    #[test]
    fn a_key_of_the_wrong_length_makes_the_line_invalid() {
        // twenty-nine octets, one short
        let short = base64_encode(&[0x41; 29]);
        assert!(
            line(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{short}"))
                .policy()
                .is_none()
        );
        let long = base64_encode(&[0x41; 31]);
        assert!(
            line(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{long}"))
                .policy()
                .is_none()
        );
    }

    // RFC 6188 §4, RFC 7714 §14.1: the widths the new suites carry, and their
    // own names round-tripping through `from_name`.
    #[test]
    fn the_new_suites_have_the_widths_their_rfcs_give_them() {
        assert_eq!(CryptoSuite::Aes256Cm80.key_len(), 32);
        assert_eq!(CryptoSuite::Aes256Cm80.salt_len(), 14);
        assert_eq!(CryptoSuite::Aes256Cm32.key_len(), 32);
        assert_eq!(CryptoSuite::Aes256Cm32.salt_len(), 14);
        assert_eq!(CryptoSuite::AeadAes128Gcm.key_len(), 16);
        assert_eq!(CryptoSuite::AeadAes128Gcm.salt_len(), 12);
        assert_eq!(CryptoSuite::AeadAes256Gcm.key_len(), 32);
        assert_eq!(CryptoSuite::AeadAes256Gcm.salt_len(), 12);
        assert!(!CryptoSuite::Aes256Cm80.is_aead());
        assert!(CryptoSuite::AeadAes128Gcm.is_aead());

        for suite in CryptoSuite::STRENGTH {
            assert_eq!(
                CryptoSuite::from_name(suite.name()),
                Some(suite),
                "{}",
                suite.name()
            );
        }
    }

    /// A line for each new suite, with a key and salt of its own width,
    /// round-trips exactly as the three RFC 4568 suites already do.
    #[test]
    fn the_new_suites_round_trip_a_key_and_salt_of_their_own_width() {
        for suite in [
            CryptoSuite::Aes256Cm80,
            CryptoSuite::Aes256Cm32,
            CryptoSuite::AeadAes128Gcm,
            CryptoSuite::AeadAes256Gcm,
        ] {
            let keys = base64_encode(&vec![0x5a_u8; suite.key_salt_len()]);
            let policy = line(&format!("1 {} inline:{keys}", suite.name()))
                .policy()
                .unwrap_or_else(|| panic!("{} with a correctly sized key", suite.name()));
            assert_eq!(policy.suite, suite);
            let key = policy.keys.first().expect("one key");
            assert_eq!(key.keys.key().len(), suite.key_len(), "{}", suite.name());
            assert_eq!(key.keys.salt().len(), suite.salt_len(), "{}", suite.name());

            // one octet short of the suite's own width is refused, not
            // silently accepted under some other suite's length
            let short = base64_encode(&vec![0x5a_u8; suite.key_salt_len() - 1]);
            assert!(
                line(&format!("1 {} inline:{short}", suite.name()))
                    .policy()
                    .is_none(),
                "{} took a key one octet short",
                suite.name()
            );
        }
    }

    #[test]
    fn a_lifetime_past_the_suite_maximum_makes_the_line_invalid() {
        let keys = base64_encode(&[0x41; 30]);
        // §6.2: 2^31 SRTCP packets is the lower of the two limits
        assert!(
            line(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{keys}|2^31"))
                .policy()
                .is_some()
        );
        assert!(
            line(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{keys}|2^32"))
                .policy()
                .is_none()
        );
    }

    #[test]
    fn the_rules_about_leading_zeroes_and_lengths() {
        let keys = base64_encode(&[0x41; 30]);
        for tail in [
            "|02^20",     // a leading zero on the lifetime
            "|0",         // and a lifetime of nothing
            "|01:4",      // one on the identifier
            "|1:04",      // one on its length
            "|1:0",       // a field of no octets
            "|1:129",     // "its value exceeds 128"
            "|2^20|2^21", // two lifetimes
            "|1:4|2^20",  // and a lifetime after an identifier
        ] {
            assert!(
                line(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{keys}{tail}"))
                    .policy()
                    .is_none(),
                "{tail} should have been refused"
            );
        }
    }

    #[test]
    fn an_unknown_suite_is_refused_rather_than_guessed() {
        let keys = base64_encode(&[0x41; 30]);
        assert!(
            line(&format!("1 AES_CM_512_HMAC_SHA1_80 inline:{keys}"))
                .policy()
                .is_none()
        );
        assert!(
            line(&format!("1 F8_128_HMAC_SHA1_32 inline:{keys}"))
                .policy()
                .is_none(),
            "the token the grammar prints and erratum 6808 corrects"
        );
    }

    #[test]
    fn the_tokens_are_read_whatever_their_case() {
        let keys = base64_encode(&[0x41; 30]);
        let policy = line(&format!("1 aes_cm_128_hmac_sha1_80 INLINE:{keys}"))
            .policy()
            .expect("valid");
        assert_eq!(policy.suite, CryptoSuite::AesCm80);
    }

    #[test]
    fn the_session_parameters_are_read_and_written_back() {
        let keys = base64_encode(&[0x41; 30]);
        let crypto = line(&format!(
            "1 AES_CM_128_HMAC_SHA1_32 inline:{keys} KDR=5 UNENCRYPTED_SRTCP WSH=128"
        ));
        let policy = crypto.policy().expect("valid");
        assert_eq!(policy.params.kdr, Some(5));
        assert!(policy.params.unencrypted_rtcp);
        assert!(!policy.params.unencrypted_rtp);
        assert_eq!(policy.params.window, Some(128));
        assert_eq!(policy.to_crypto().to_value(), crypto.to_value());
    }

    #[test]
    fn a_session_parameter_out_of_range_makes_the_line_invalid() {
        let keys = base64_encode(&[0x41; 30]);
        assert!(
            line(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{keys} KDR=25"))
                .policy()
                .is_none()
        );
        assert!(
            line(&format!("1 AES_CM_128_HMAC_SHA1_80 inline:{keys} WSH=63"))
                .policy()
                .is_none(),
            "§6.3.6 puts the minimum at 64"
        );
    }

    /// §6.3.7 is the opposite of the usual extension rule, and reading it the
    /// usual way produces a stack that quietly ignores what a peer required.
    /// A parameter that did not opt out of mattering makes the line invalid.
    #[test]
    fn a_parameter_we_do_not_know_makes_the_line_one_we_cannot_be_held_to() {
        let keys = base64_encode(&[0x41; 30]);
        let crypto = line(&format!(
            "1 AES_CM_128_HMAC_SHA1_80 inline:{keys} FEC_ORDER=FEC_SRTP"
        ));
        assert_eq!(crypto.session_params.len(), 1, "the line still parses");
        assert!(
            crypto.policy().is_none(),
            "an unknown mandatory parameter must make the attribute invalid"
        );
    }

    /// And the half that keeps the rule usable: whoever defines a parameter
    /// can say it is safe to ignore, by writing it with a leading dash.
    #[test]
    fn a_parameter_written_as_optional_is_ignored_rather_than_refused() {
        let keys = base64_encode(&[0x41; 30]);
        let crypto = line(&format!(
            "1 AES_CM_128_HMAC_SHA1_80 inline:{keys} -SOMETHING_LATER=1"
        ));
        let policy = crypto.policy().expect("the dash says it may be ignored");
        assert_eq!(policy.params, SessionParams::new(), "and it was ignored");
    }

    #[test]
    fn two_keys_need_identifiers_to_tell_them_apart() {
        let first = base64_encode(&[0x41; 30]);
        let second = base64_encode(&[0x42; 30]);
        assert!(
            line(&format!(
                "1 AES_CM_128_HMAC_SHA1_80 inline:{first}|1:4;inline:{second}|2:4"
            ))
            .policy()
            .is_some()
        );
        assert!(
            line(&format!(
                "1 AES_CM_128_HMAC_SHA1_80 inline:{first};inline:{second}"
            ))
            .policy()
            .is_none()
        );
    }

    #[test]
    fn a_key_written_and_read_back_is_the_same_key() {
        let key = [0x0f_u8; MASTER_KEY];
        let salt = [0xf0_u8; MASTER_SALT];
        let policy = CryptoPolicy::new(1, CryptoSuite::AesF8, KeySalt::new(&key, &salt));
        let text = policy.to_crypto().to_value();
        let back = Crypto::parse(&text)
            .expect("valid")
            .policy()
            .expect("valid");
        let read = back.keys.first().expect("one key");
        assert_eq!(read.keys.key(), key);
        assert_eq!(read.keys.salt(), salt);
        assert_eq!(back.suite, CryptoSuite::AesF8);
    }

    #[test]
    fn the_keys_are_not_in_the_debug_output() {
        let keys = KeySalt::new(&[0xab; MASTER_KEY], &[0xcd; MASTER_SALT]);
        let printed = format!("{:?}", Inline::new(keys));
        assert!(printed.contains("redacted"), "{printed}");
        assert!(!printed.contains("171"), "{printed}");
        assert!(!printed.contains("ab"), "{printed}");
    }

    #[test]
    fn the_defaults_say_encrypt_and_authenticate_everything() {
        let params = SessionParams::new();
        assert!(!params.unencrypted_rtp);
        assert!(!params.unencrypted_rtcp);
        assert!(!params.unauthenticated_rtp);
        assert_eq!(params.kdr, None);
        assert!(params.to_values().is_empty());
    }
}
