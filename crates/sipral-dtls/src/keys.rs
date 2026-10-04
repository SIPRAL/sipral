// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The P-256 keys of a handshake: the ephemeral ECDH key each side sends in
//! ServerKeyExchange or ClientKeyExchange, and the ECDSA key a certificate
//! carries and the handshake signs with.
//!
//! The arithmetic is the `p256` crate's. What this module adds is the
//! handshake's view of it: keys made from the caller's randomness, points
//! read and written only in the uncompressed form RFC 8422 §5.1.2 still
//! allows, a peer's point checked to be on the curve before anything is done
//! with it (§5.11), a shared secret that keeps its leading zeros (§5.10), and
//! signatures as the DER `Ecdsa-Sig-Value` the wire carries (§5.4).
//!
//! And the one key that is not P-256: an RSA key on the peer's side, which
//! this end checks signatures with and never signs with. FreeSWITCH, left as
//! it ships, certifies its DTLS-SRTP end with an RSA-4096 key, and a peer
//! like that cannot be keyed with at all without it.

use core::fmt;

use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{DerSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::{PublicKey, SecretKey};
use rsa::traits::PublicKeyParts;
use rsa::{BoxedUint, Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::handshake::SignatureAndHash;
use crate::{Error, Random};

/// Octets in an uncompressed P-256 point: the form octet, then x and y.
pub const POINT_LEN: usize = 65;
/// Octets in a P-256 private scalar.
pub const SCALAR_LEN: usize = 32;
/// Octets in the ECDH shared secret, the x-coordinate of the shared point.
pub const SHARED_SECRET_LEN: usize = 32;

/// The form octet of an uncompressed point (RFC 8422 §5.4.1).
const UNCOMPRESSED: u8 = 0x04;

/// Draws before a source is declared broken. A uniformly random 32-octet
/// string fails to be a P-256 scalar — zero, or not below the group order —
/// with probability about 2^-32, so one refusal is bad luck and thirty-two in
/// a row are a source returning something other than random octets.
const ATTEMPTS: usize = 32;

fn draw<R, K>(random: &mut R, make: impl Fn(&[u8]) -> Option<K>) -> Result<K, Error>
where
    R: Random + ?Sized,
{
    let mut bytes = Zeroizing::new([0u8; SCALAR_LEN]);
    for _ in 0..ATTEMPTS {
        random.fill(bytes.as_mut_slice());
        if let Some(key) = make(bytes.as_slice()) {
            return Ok(key);
        }
    }
    Err(Error::RandomRejected)
}

/// Refuse anything that is not an uncompressed point by its shape, before the
/// curve equation is even looked at: RFC 8422 deprecates the compressed and
/// hybrid forms, and a peer that sends one is not following it.
fn uncompressed(point: &[u8]) -> Result<&[u8], Error> {
    if point.len() != POINT_LEN || point.first() != Some(&UNCOMPRESSED) {
        return Err(Error::InvalidPublicKey);
    }
    Ok(point)
}

fn to_array(bytes: &[u8]) -> [u8; POINT_LEN] {
    let mut out = [0u8; POINT_LEN];
    for (slot, byte) in out.iter_mut().zip(bytes) {
        *slot = *byte;
    }
    out
}

/// An ECDSA P-256 private key.
///
/// Wiped when dropped, and never printed.
#[derive(Clone)]
pub struct EcdsaKey {
    signing: SigningKey,
}

impl EcdsaKey {
    /// A new key from the caller's randomness.
    ///
    /// # Errors
    ///
    /// [`Error::RandomRejected`] when the source keeps producing octets no key
    /// can be made from.
    pub fn generate<R: Random + ?Sized>(random: &mut R) -> Result<Self, Error> {
        draw(random, |bytes| {
            SigningKey::from_slice(bytes)
                .ok()
                .map(|signing| Self { signing })
        })
    }

    /// The key whose private scalar is `scalar`, big-endian: one kept from
    /// before, which RFC 8827 §6.5 has an application be able to reuse.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] for zero, or a value not below the group order.
    pub fn from_scalar(scalar: &[u8; SCALAR_LEN]) -> Result<Self, Error> {
        SigningKey::from_slice(scalar)
            .map(|signing| Self { signing })
            .map_err(|_| Error::IllegalValue)
    }

    /// The public key, uncompressed.
    #[must_use]
    pub fn public_key(&self) -> [u8; POINT_LEN] {
        to_array(self.signing.verifying_key().to_sec1_point(false).as_bytes())
    }

    /// The public key, as a peer would hold it.
    #[must_use]
    pub fn peer_key(&self) -> PeerKey {
        PeerKey {
            verifying: *self.signing.verifying_key(),
        }
    }

    /// ECDSA over SHA-256 of `message`, DER-encoded.
    ///
    /// The per-signature secret `k` is derived from the key and the digest as
    /// RFC 6979 describes, so signing draws no randomness and a weak source
    /// cannot leak the key through a repeated `k`.
    ///
    /// # Errors
    ///
    /// [`Error::SigningFailed`] if the primitive refuses, which a valid key
    /// and a SHA-256 digest never make it do.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature: DerSignature = self
            .signing
            .try_sign(message)
            .map_err(|_| Error::SigningFailed)?;
        Ok(signature.as_bytes().to_vec())
    }

    /// ECDSA over a SHA-256 digest computed elsewhere — a
    /// [`crate::handshake::Transcript`] hash, for CertificateVerify.
    ///
    /// # Errors
    ///
    /// As [`EcdsaKey::sign`].
    pub fn sign_digest(&self, digest: &[u8; 32]) -> Result<Vec<u8>, Error> {
        let signature: DerSignature = self
            .signing
            .sign_prehash(digest)
            .map_err(|_| Error::SigningFailed)?;
        Ok(signature.as_bytes().to_vec())
    }
}

impl fmt::Debug for EcdsaKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaKey").finish_non_exhaustive()
    }
}

/// A P-256 public key belonging to the peer: from its certificate, for
/// checking what it signed.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerKey {
    verifying: VerifyingKey,
}

impl PeerKey {
    /// Read an uncompressed point, and check it lies on the curve.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] for any other length or form octet, for a
    /// point off the curve, and for the point at infinity.
    pub fn from_uncompressed(point: &[u8]) -> Result<Self, Error> {
        let verifying = VerifyingKey::from_sec1_bytes(uncompressed(point)?)
            .map_err(|_| Error::InvalidPublicKey)?;
        Ok(Self { verifying })
    }

    /// The point, uncompressed.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; POINT_LEN] {
        to_array(self.verifying.to_sec1_point(false).as_bytes())
    }

    /// Check a DER-encoded ECDSA signature over SHA-256 of `message`.
    ///
    /// # Errors
    ///
    /// [`Error::BadSignature`] when the signature is not DER, is not a pair of
    /// integers in range, or does not verify.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let signature = DerSignature::from_bytes(signature).map_err(|_| Error::BadSignature)?;
        self.verifying
            .verify(message, &signature)
            .map_err(|_| Error::BadSignature)
    }

    /// Check a DER-encoded ECDSA signature over a SHA-256 digest computed
    /// elsewhere.
    ///
    /// # Errors
    ///
    /// As [`PeerKey::verify`].
    pub fn verify_digest(&self, digest: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
        let signature = DerSignature::from_bytes(signature).map_err(|_| Error::BadSignature)?;
        self.verifying
            .verify_prehash(digest, &signature)
            .map_err(|_| Error::BadSignature)
    }
}

impl fmt::Debug for PeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerKey").finish_non_exhaustive()
    }
}

/// The shortest RSA modulus accepted, in bits: RFC 9325 §4.5, "servers MUST
/// authenticate using certificates with at least a 2048-bit modulus".
pub const MIN_RSA_BITS: u32 = 2048;
/// The longest, in bits: the ceiling the primitive itself sets. A peer's key
/// is read only once its certificate has matched the fingerprint signalling
/// named, so the size is that peer's own choice; checking a signature under
/// the largest key still takes one exponentiation by an exponent of at most
/// 33 bits.
pub const MAX_RSA_BITS: u32 = 8192;

/// An RSA public key belonging to the peer, from its certificate: for
/// checking what it signed, with RSASSA-PKCS1-v1_5 over SHA-256, the one RSA
/// scheme this crate offers (RFC 5246 §7.4.1.4.1).
#[derive(Clone, PartialEq, Eq)]
pub struct RsaPeerKey {
    key: RsaPublicKey,
}

impl RsaPeerKey {
    /// A key from the big-endian magnitudes of its modulus and exponent, as
    /// an `RSAPublicKey` carries them (RFC 3279 §2.3.1).
    ///
    /// # Errors
    ///
    /// [`Error::UnacceptableRsaKey`] for a modulus shorter than
    /// [`MIN_RSA_BITS`] or longer than [`MAX_RSA_BITS`], an even modulus, an
    /// exponent below 2 or above 2^33 - 1, or one not below the modulus.
    pub fn from_parts(modulus: &[u8], exponent: &[u8]) -> Result<Self, Error> {
        let n = BoxedUint::from_be_slice_vartime(modulus);
        let bits = n.bits_vartime();
        if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
            return Err(Error::UnacceptableRsaKey);
        }
        let e = BoxedUint::from_be_slice_vartime(exponent);
        let max = usize::try_from(MAX_RSA_BITS).map_err(|_| Error::UnacceptableRsaKey)?;
        RsaPublicKey::new_with_max_size(n, e, max)
            .map(|key| Self { key })
            .map_err(|_| Error::UnacceptableRsaKey)
    }

    /// Octets in the modulus, which is how long every signature under this
    /// key is.
    #[must_use]
    pub fn len(&self) -> usize {
        self.key.size()
    }

    /// Never true: a modulus has octets. Here because a type with `len`
    /// is expected to answer it.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check an RSASSA-PKCS1-v1_5 signature over a SHA-256 digest computed
    /// elsewhere.
    ///
    /// The padded block is rebuilt from the digest and compared whole
    /// (RFC 8017 §8.2.2 step 3-4), not parsed, so nothing a forger puts
    /// after the digest or inside the padding is ever skipped over.
    ///
    /// # Errors
    ///
    /// [`Error::BadSignature`] for a signature that is not exactly as long as
    /// the modulus (RFC 8017 §8.2.2 step 1), is not below it, or does not
    /// verify.
    pub fn verify_digest(&self, digest: &[u8; 32], signature: &[u8]) -> Result<(), Error> {
        if signature.len() != self.len() {
            return Err(Error::BadSignature);
        }
        self.key
            .verify(Pkcs1v15Sign::new::<Sha256>(), digest, signature)
            .map_err(|_| Error::BadSignature)
    }
}

impl fmt::Debug for RsaPeerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RsaPeerKey")
            .field("bits", &self.key.n().bits_vartime())
            .finish_non_exhaustive()
    }
}

/// The public key a peer's certificate carries, of either kind a DTLS-SRTP
/// peer is found with: P-256, which this end uses itself and every WebRTC
/// peer does, or RSA.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertifiedKey {
    /// An ECDSA key on P-256.
    P256(PeerKey),
    /// An RSA key.
    Rsa(RsaPeerKey),
}

impl CertifiedKey {
    /// The signature and hash pair a signature under this key has to name:
    /// each kind of key has exactly one this crate verifies.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAndHash {
        match self {
            Self::P256(_) => SignatureAndHash::ECDSA_SHA256,
            Self::Rsa(_) => SignatureAndHash::RSA_PKCS1_SHA256,
        }
    }

    /// Check a signature over a SHA-256 digest computed elsewhere, made with
    /// the pair `algorithm` names.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] when `algorithm` is not the pair this kind of
    /// key signs with — an ECDSA signature claimed under an RSA key, say —
    /// and [`Error::BadSignature`] when it is and the signature does not
    /// verify.
    pub fn verify_digest(
        &self,
        algorithm: SignatureAndHash,
        digest: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), Error> {
        if algorithm != self.algorithm() {
            return Err(Error::IllegalValue);
        }
        match self {
            Self::P256(key) => key.verify_digest(digest, signature),
            Self::Rsa(key) => key.verify_digest(digest, signature),
        }
    }

    /// As [`CertifiedKey::verify_digest`], over `message` itself.
    ///
    /// # Errors
    ///
    /// As [`CertifiedKey::verify_digest`].
    pub fn verify(
        &self,
        algorithm: SignatureAndHash,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        self.verify_digest(algorithm, &Sha256::digest(message).into(), signature)
    }
}

/// An ephemeral ECDH P-256 private key, for one handshake.
///
/// [`EphemeralKey::agree`] consumes it, so a key cannot be used for a second
/// exchange by mistake. Wiped when dropped, and never printed.
pub struct EphemeralKey {
    secret: SecretKey,
}

impl EphemeralKey {
    /// A new key from the caller's randomness.
    ///
    /// # Errors
    ///
    /// [`Error::RandomRejected`] when the source keeps producing octets no key
    /// can be made from.
    pub fn generate<R: Random + ?Sized>(random: &mut R) -> Result<Self, Error> {
        draw(random, |bytes| {
            SecretKey::from_slice(bytes)
                .ok()
                .map(|secret| Self { secret })
        })
    }

    /// The key whose private scalar is `scalar`, big-endian.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] for zero, or a value not below the group order.
    pub fn from_scalar(scalar: &[u8; SCALAR_LEN]) -> Result<Self, Error> {
        SecretKey::from_slice(scalar)
            .map(|secret| Self { secret })
            .map_err(|_| Error::IllegalValue)
    }

    /// The public key to send, uncompressed.
    #[must_use]
    pub fn public_key(&self) -> [u8; POINT_LEN] {
        to_array(self.secret.public_key().to_sec1_point(false).as_bytes())
    }

    /// The pre-master secret shared with the peer whose public point is
    /// `peer_point`: the x-coordinate of the shared point, all 32 octets
    /// (RFC 8422 §5.10: "leading zeros found in this octet string MUST NOT be
    /// truncated").
    ///
    /// # Errors
    ///
    /// [`Error::InvalidPublicKey`] for a point that is not uncompressed, not
    /// on the curve, or the point at infinity — the validation RFC 8422 §5.11
    /// requires of both sides.
    pub fn agree(self, peer_point: &[u8]) -> Result<PreMasterSecret, Error> {
        let peer = PublicKey::from_sec1_bytes(uncompressed(peer_point)?)
            .map_err(|_| Error::InvalidPublicKey)?;
        let shared = self.secret.diffie_hellman(&peer);
        let mut secret = Zeroizing::new([0u8; SHARED_SECRET_LEN]);
        for (slot, byte) in secret.iter_mut().zip(shared.raw_secret_bytes().iter()) {
            *slot = *byte;
        }
        Ok(PreMasterSecret(secret))
    }
}

impl fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EphemeralKey").finish_non_exhaustive()
    }
}

/// The ECDHE pre-master secret, input to [`crate::prf::MasterSecret`].
///
/// Wiped when dropped, and never printed.
pub struct PreMasterSecret(Zeroizing<[u8; SHARED_SECRET_LEN]>);

impl PreMasterSecret {
    /// The secret's octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }
}

impl fmt::Debug for PreMasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreMasterSecret").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::testing::{Counter, Stuck};
    use sha2::{Digest, Sha256};

    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let s: String = s.split_whitespace().collect();
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    fn point(x: &str, y: &str) -> [u8; POINT_LEN] {
        let mut out = [0u8; POINT_LEN];
        out[0] = 4;
        out[1..33].copy_from_slice(&hex::<32>(x));
        out[33..].copy_from_slice(&hex::<32>(y));
        out
    }

    // RFC 5903 §8.1, the 256-bit random ECP group
    const I: &str = "C88F01F5 10D9AC3F 70A292DA A2316DE5 44E9AAB8 AFE84049 C62A9C57 862D1433";
    const GIX: &str = "DAD0B653 94221CF9 B051E1FE CA5787D0 98DFE637 FC90B9EF 945D0C37 72581180";
    const GIY: &str = "5271A046 1CDB8252 D61F1C45 6FA3E59A B1F45B33 ACCF5F58 389E0577 B8990BB3";
    const R: &str = "C6EF9C5D 78AE012A 011164AC B397CE20 88685D8F 06BF9BE0 B283AB46 476BEE53";
    const GRX: &str = "D12DFB52 89C8D4F8 1208B702 70398C34 2296970A 0BCCB74C 736FC755 4494BF63";
    const GRY: &str = "56FBF3CA 366CC23E 8157854C 13C58D6A AC23F046 ADA30F83 53E74F33 039872AB";
    const GIRX: &str = "D6840F6B 42F6EDAF D13116E0 E1256520 2FEF8E9E CE7DCE03 812464D0 4B9442DE";

    #[test]
    fn ecdh_reproduces_rfc_5903() {
        let initiator = EphemeralKey::from_scalar(&hex(I)).unwrap();
        let responder = EphemeralKey::from_scalar(&hex(R)).unwrap();
        assert_eq!(initiator.public_key(), point(GIX, GIY));
        assert_eq!(responder.public_key(), point(GRX, GRY));
        let ours = initiator.agree(&point(GRX, GRY)).unwrap();
        let theirs = responder.agree(&point(GIX, GIY)).unwrap();
        assert_eq!(ours.as_bytes(), &hex::<32>(GIRX));
        assert_eq!(theirs.as_bytes(), &hex::<32>(GIRX));
    }

    #[test]
    fn a_point_that_is_not_an_uncompressed_curve_point_is_refused() {
        let good = point(GRX, GRY);
        let mut off_curve = good;
        off_curve[64] ^= 1;
        let mut compressed = vec![0x02 | (good[64] & 1)];
        compressed.extend_from_slice(&good[1..33]);
        let mut hybrid = good;
        hybrid[0] = 0x06 | (good[64] & 1);
        let zeros = {
            let mut z = [0u8; POINT_LEN];
            z[0] = 4;
            z
        };
        let cases: [(&str, &[u8]); 7] = [
            ("off the curve", &off_curve),
            ("compressed", &compressed),
            ("hybrid", &hybrid),
            ("x and y zero", &zeros),
            ("infinity", &[0]),
            ("short", &good[..64]),
            ("empty", &[]),
        ];
        for (what, bytes) in cases {
            assert_eq!(
                PeerKey::from_uncompressed(bytes).err(),
                Some(Error::InvalidPublicKey),
                "{what}"
            );
            let key = EphemeralKey::from_scalar(&hex(I)).unwrap();
            assert_eq!(
                key.agree(bytes).err(),
                Some(Error::InvalidPublicKey),
                "{what}"
            );
        }
        assert!(PeerKey::from_uncompressed(&good).is_ok());
    }

    // RFC 6979 A.2.5, ECDSA over P-256 with SHA-256
    const X: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
    const UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
    const UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

    fn der(r: &[u8], s: &[u8]) -> Vec<u8> {
        // Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }, each integer
        // minimal and positive
        fn integer(value: &[u8]) -> Vec<u8> {
            let trimmed: Vec<u8> = value.iter().copied().skip_while(|&b| b == 0).collect();
            let mut content = trimmed;
            if content.first().is_none_or(|&b| b & 0x80 != 0) {
                content.insert(0, 0);
            }
            let mut out = vec![0x02, u8::try_from(content.len()).unwrap()];
            out.extend(content);
            out
        }
        let mut body = integer(r);
        body.extend(integer(s));
        let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend(body);
        out
    }

    #[test]
    fn ecdsa_reproduces_rfc_6979() {
        let key = EcdsaKey::from_scalar(&hex(X)).unwrap();
        assert_eq!(key.public_key(), point(UX, UY));

        let sample = der(
            &hex::<32>("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"),
            &hex::<32>("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"),
        );
        assert_eq!(key.sign(b"sample").unwrap(), sample);
        let digest: [u8; 32] = Sha256::digest(b"sample").into();
        assert_eq!(key.sign_digest(&digest).unwrap(), sample);

        // s here starts 0x01, so it is encoded one octet shorter than r
        let test = der(
            &hex::<32>("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367"),
            &hex::<32>("019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"),
        );
        assert_eq!(test[1], 0x45);
        assert_eq!(key.sign(b"test").unwrap(), test);

        let peer = PeerKey::from_uncompressed(&point(UX, UY)).unwrap();
        assert_eq!(peer, key.peer_key());
        assert_eq!(peer.to_uncompressed(), point(UX, UY));
        assert_eq!(peer.verify(b"sample", &sample), Ok(()));
        assert_eq!(peer.verify_digest(&digest, &sample), Ok(()));
        assert_eq!(peer.verify(b"test", &test), Ok(()));
    }

    #[test]
    fn a_signature_verifies_only_for_its_message_key_and_encoding() {
        let key = EcdsaKey::from_scalar(&hex(X)).unwrap();
        let peer = key.peer_key();
        let signature = key.sign(b"sample").unwrap();

        // the baseline every negative case below is a variation on: unless
        // this holds, refusing an altered message, key or encoding proves
        // nothing about what changed
        assert_eq!(peer.verify(b"sample", &signature), Ok(()));
        assert_eq!(peer.verify(b"samplf", &signature), Err(Error::BadSignature));
        for position in 0..signature.len() {
            let mut altered = signature.clone();
            altered[position] ^= 0x01;
            assert_eq!(
                peer.verify(b"sample", &altered),
                Err(Error::BadSignature),
                "octet {position}"
            );
        }
        // BER, not DER: r given a redundant leading zero
        let mut padded = vec![0x30, signature[1] + 1, 0x02, signature[3] + 1, 0x00];
        padded.extend_from_slice(&signature[4..]);
        assert_eq!(peer.verify(b"sample", &padded), Err(Error::BadSignature));
        assert_eq!(peer.verify(b"sample", &[]), Err(Error::BadSignature));

        let other = EcdsaKey::generate(&mut Counter::new(9)).unwrap().peer_key();
        assert_eq!(
            other.verify(b"sample", &signature),
            Err(Error::BadSignature)
        );
    }

    /// A source whose first draw is all ones — above the group order — and
    /// whose every later draw is the counter's.
    struct OnceBad(Counter, bool);

    impl Random for OnceBad {
        fn fill(&mut self, dest: &mut [u8]) {
            if self.1 {
                self.0.fill(dest);
            } else {
                dest.fill(0xFF);
                self.1 = true;
            }
        }
    }

    #[test]
    fn keys_come_from_the_callers_randomness_and_a_broken_source_is_caught() {
        let a = EcdsaKey::generate(&mut Counter::new(1)).unwrap();
        let b = EcdsaKey::generate(&mut Counter::new(1)).unwrap();
        let c = EcdsaKey::generate(&mut Counter::new(2)).unwrap();
        assert_eq!(a.public_key(), b.public_key());
        assert_ne!(a.public_key(), c.public_key());
        let e = EphemeralKey::generate(&mut Counter::new(1)).unwrap();
        assert_eq!(e.public_key(), a.public_key());

        // zero is not a scalar, and neither is anything at or above the order
        assert_eq!(
            EcdsaKey::generate(&mut Stuck(0)).err(),
            Some(Error::RandomRejected)
        );
        assert_eq!(
            EphemeralKey::generate(&mut Stuck(0xFF)).err(),
            Some(Error::RandomRejected)
        );
        assert_eq!(
            EcdsaKey::from_scalar(&[0; 32]).err(),
            Some(Error::IllegalValue)
        );
        assert_eq!(
            EphemeralKey::from_scalar(&[0xFF; 32]).err(),
            Some(Error::IllegalValue)
        );

        // one unusable draw is retried, not reported
        let retried = EcdsaKey::generate(&mut OnceBad(Counter::new(1), false)).unwrap();
        assert_eq!(retried.public_key(), a.public_key());
    }

    #[test]
    fn both_ends_of_a_generated_exchange_agree() {
        let mut random = Counter::new(77);
        let client = EphemeralKey::generate(&mut random).unwrap();
        let server = EphemeralKey::generate(&mut random).unwrap();
        let client_point = client.public_key();
        let server_point = server.public_key();
        assert_eq!(
            client.agree(&server_point).unwrap().as_bytes(),
            server.agree(&client_point).unwrap().as_bytes()
        );
    }

    #[test]
    fn no_key_is_printed() {
        let printed = format!(
            "{:?} {:?} {:?} {:?}",
            EcdsaKey::from_scalar(&hex(X)).unwrap(),
            EphemeralKey::from_scalar(&hex(I)).unwrap(),
            EphemeralKey::from_scalar(&hex(I))
                .unwrap()
                .agree(&point(GRX, GRY))
                .unwrap(),
            EcdsaKey::from_scalar(&hex(X)).unwrap().peer_key(),
        );
        assert_eq!(
            printed,
            "EcdsaKey { .. } EphemeralKey { .. } PreMasterSecret { .. } PeerKey { .. }"
        );
    }
}
