// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! `AEAD_AES_128_GCM` and `AEAD_AES_256_GCM` (RFC 7714), over the `aes-gcm`
//! crate: the same, already-vetted dependency `sipral-dtls` seals its own
//! records with (`crates/sipral-dtls/src/record/protection.rs`).
//!
//! Everything RFC 7714-specific — the IV formation, the associated data, the
//! SRTCP E-bit and index placement — is `session.rs`'s. What is here is the
//! bare primitive: seal a buffer in place under a nonce and associated data
//! and hand back the sixteen-octet tag, or open one and verify it.

use aes_gcm::aead::{AeadInOut, Nonce, Tag};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit};

use zeroize::Zeroize;

use super::cipher::Exhausted;

/// The AEAD authentication tag length RFC 7714 §10 and §13.2 fix at sixteen
/// octets for both suites, and require in full — no truncated GCM tag.
pub(crate) const TAG: usize = 16;

/// The nonce (nee "salt") length RFC 7714 §8.1 fixes at twelve octets for
/// both suites, where AES-CM and f8 use fourteen.
pub(crate) const SALT: usize = 12;

/// The tag did not match: forged, corrupted, or opened under the wrong key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TagMismatch;

/// One suite's cipher, keyed once per session — the AEAD counterpart of
/// [`super::cipher::Counter`].
#[expect(
    clippy::large_enum_variant,
    reason = "the difference is one AES key schedule, and there is one of these per session, not per packet"
)]
pub(crate) enum Gcm {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
}

impl Gcm {
    /// A key of sixteen or thirty-two octets, exactly as
    /// [`super::cipher::Counter::new`] takes one — every caller sizes the key
    /// from a [`super::Suite`] first.
    ///
    /// The key is staged in a buffer of the cipher's own key type, which is
    /// wiped once the key schedule is made from it.
    pub(crate) fn new(key: &[u8]) -> Self {
        if key.len() == 32 {
            let mut staged = aes_gcm::Key::<Aes256Gcm>::default();
            staged.copy_from_slice(key);
            let cipher = Self::Aes256(Aes256Gcm::new(&staged));
            staged.zeroize();
            cipher
        } else {
            let mut staged = aes_gcm::Key::<Aes128Gcm>::default();
            if let Some(head) = staged.get_mut(..key.len().min(16)) {
                head.copy_from_slice(key.get(..key.len().min(16)).unwrap_or_default());
            }
            let cipher = Self::Aes128(Aes128Gcm::new(&staged));
            staged.zeroize();
            cipher
        }
    }

    /// Seal `buffer` in place under `iv` and `aad`, returning the tag.
    ///
    /// # Errors
    /// [`Exhausted`] past RFC 7714 §10's `P_MAX`, which no RTP packet nears.
    pub(crate) fn seal(
        &self,
        iv: &[u8; SALT],
        aad: &[u8],
        buffer: &mut [u8],
    ) -> Result<[u8; TAG], Exhausted> {
        let tag = match self {
            Self::Aes128(cipher) => cipher
                .encrypt_inout_detached(&Nonce::<Aes128Gcm>::from(*iv), aad, buffer.into())
                .map_err(|_| Exhausted)?,
            Self::Aes256(cipher) => cipher
                .encrypt_inout_detached(&Nonce::<Aes256Gcm>::from(*iv), aad, buffer.into())
                .map_err(|_| Exhausted)?,
        };
        let mut out = [0_u8; TAG];
        out.copy_from_slice(tag.as_slice());
        Ok(out)
    }

    /// Verify `tag` and open `buffer` in place under `iv` and `aad`.
    ///
    /// # Errors
    /// [`TagMismatch`] when the tag does not match; `buffer` is then unchanged
    /// (`aes-gcm` 0.11 verifies first), which `Security`'s retry relies on.
    pub(crate) fn open(
        &self,
        iv: &[u8; SALT],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; TAG],
    ) -> Result<(), TagMismatch> {
        match self {
            Self::Aes128(cipher) => cipher
                .decrypt_inout_detached(
                    &Nonce::<Aes128Gcm>::from(*iv),
                    aad,
                    buffer.into(),
                    &Tag::<Aes128Gcm>::from(*tag),
                )
                .map_err(|_| TagMismatch),
            Self::Aes256(cipher) => cipher
                .decrypt_inout_detached(
                    &Nonce::<Aes256Gcm>::from(*iv),
                    aad,
                    buffer.into(),
                    &Tag::<Aes256Gcm>::from(*tag),
                )
                .map_err(|_| TagMismatch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{hex, unhex, unhexn};
    use super::{Gcm, SALT, TAG};

    /// The RTP packet every vector in RFC 7714 §16 protects: a twelve-octet
    /// header (`AAD`) and the thirty-eight-octet ASCII payload "Gallia est
    /// omnis divisa in partes tres" (`PT`), under one IV both GCM suites
    /// share because they are keyed differently, not addressed differently.
    const RTP_IV: &str = "51753c6580c2726f20718414";
    const RTP_AAD: &str = "8040f17b8041f8d35501a0b2";
    const RTP_PT: &str =
        "47616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573";
    /// The same packet again, in full, for §16.1.3/§16.2.3's tagging-only
    /// vectors, which take the whole thing as associated data.
    const RTP_WHOLE_AS_AAD: &str = "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064\
         697669736120696e207061727465732074726573";

    // RFC 7714 §16.1.1/§16.1.2: SRTP AEAD_AES_128_GCM encryption, decryption
    // and tag verification, byte for byte.
    #[test]
    fn rfc_7714_16_1_1_16_1_2_aead_aes_128_gcm_srtp() {
        let key: [u8; 16] = unhexn("000102030405060708090a0b0c0d0e0f");
        let iv: [u8; SALT] = unhexn(RTP_IV);
        let aad = unhex(RTP_AAD);
        let plaintext = unhex(RTP_PT);

        let cipher = Gcm::new(&key);
        let mut buffer = plaintext.clone();
        let tag = cipher
            .seal(&iv, &aad, &mut buffer)
            .expect("well within the length bound");
        assert_eq!(
            hex(&buffer),
            "f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833"
        );
        assert_eq!(hex(&tag), "899d7f27beb16a9152cf765ee4390cce");

        cipher
            .open(&iv, &aad, &mut buffer, &tag)
            .expect("the tag this suite just produced verifies");
        assert_eq!(hex(&buffer), hex(&plaintext));
    }

    // RFC 7714 §16.1.3/§16.1.4: the whole RTP packet as associated data and
    // an empty plaintext -- the shape SRTCP's E-flag=0 tagging uses.
    #[test]
    fn rfc_7714_16_1_3_16_1_4_aead_aes_128_gcm_tagging_only() {
        let key: [u8; 16] = unhexn("000102030405060708090a0b0c0d0e0f");
        let iv: [u8; SALT] = unhexn(RTP_IV);
        let aad = unhex(RTP_WHOLE_AS_AAD);

        let cipher = Gcm::new(&key);
        let mut empty: [u8; 0] = [];
        let tag = cipher
            .seal(&iv, &aad, &mut empty)
            .expect("well within the length bound");
        assert_eq!(hex(&tag), "22493f82d2bce397e9d79e3b19aa4216");
        cipher
            .open(&iv, &aad, &mut empty, &tag)
            .expect("the tag this suite just produced verifies");
    }

    // RFC 7714 §16.2.1/§16.2.2: the same packet under AEAD_AES_256_GCM.
    #[test]
    fn rfc_7714_16_2_1_16_2_2_aead_aes_256_gcm_srtp() {
        let key: [u8; 32] =
            unhexn("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv: [u8; SALT] = unhexn(RTP_IV);
        let aad = unhex(RTP_AAD);
        let plaintext = unhex(RTP_PT);

        let cipher = Gcm::new(&key);
        let mut buffer = plaintext.clone();
        let tag = cipher
            .seal(&iv, &aad, &mut buffer)
            .expect("well within the length bound");
        assert_eq!(
            hex(&buffer),
            "32b1de78a822fe12ef9f78fa332e33aab18012389a58e2f3b50b2a0276ffae0f1ba63799b87b"
        );
        assert_eq!(hex(&tag), "7aa3db36dfffd6b0f9bb7878d7a76c13");

        cipher
            .open(&iv, &aad, &mut buffer, &tag)
            .expect("the tag this suite just produced verifies");
        assert_eq!(hex(&buffer), hex(&plaintext));
    }

    // RFC 7714 §16.2.3/§16.2.4: the tagging-only shape under 256-bit GCM.
    #[test]
    fn rfc_7714_16_2_3_16_2_4_aead_aes_256_gcm_tagging_only() {
        let key: [u8; 32] =
            unhexn("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv: [u8; SALT] = unhexn(RTP_IV);
        let aad = unhex(RTP_WHOLE_AS_AAD);

        let cipher = Gcm::new(&key);
        let mut empty: [u8; 0] = [];
        let tag = cipher
            .seal(&iv, &aad, &mut empty)
            .expect("well within the length bound");
        assert_eq!(hex(&tag), "a866d5910f887463067ceefec45215d4");
        cipher
            .open(&iv, &aad, &mut empty, &tag)
            .expect("the tag this suite just produced verifies");
    }

    /// The RTCP packet RFC 7714 §17 protects, with SRTCP index `0x000005d4`.
    const RTCP_IV: &str = "517524055203726f207170bb";
    /// The eight-octet RTCP header and the E=1 ESRTCP word, the associated
    /// data when the packet is encrypted (§17.1/§17.2).
    const RTCP_AAD_ENCRYPTED: &str = "81c8000d4d617273800005d4";
    const RTCP_PT: &str =
        "4e5450314e545032525450200000042a0000e9304c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
    /// The whole packet plus the E=0 ESRTCP word, the associated data when
    /// the packet is tagged but not encrypted (§17.3/§17.4).
    const RTCP_WHOLE_AS_AAD: &str = "81c8000d4d6172734e5450314e545032525450200000042a0000e9304c75\
         6e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef000005d4";

    // RFC 7714 §17.1: SRTCP AEAD_AES_128_GCM, encryption flag set.
    #[test]
    fn rfc_7714_17_1_srtcp_aead_128_gcm_encryption() {
        let key: [u8; 16] = unhexn("000102030405060708090a0b0c0d0e0f");
        let iv: [u8; SALT] = unhexn(RTCP_IV);
        let aad = unhex(RTCP_AAD_ENCRYPTED);
        let plaintext = unhex(RTCP_PT);

        let cipher = Gcm::new(&key);
        let mut buffer = plaintext.clone();
        let tag = cipher
            .seal(&iv, &aad, &mut buffer)
            .expect("well within the length bound");
        assert_eq!(
            hex(&buffer),
            "63e94885dcdab67ca727d7662f6b7e997ff5c0f76c06f32dc676a5f1730d6fda4ce09b4686303ded0bb9275b"
        );
        assert_eq!(hex(&tag), "c84aa45896cf4d2fc5abf87245d9eade");
        cipher
            .open(&iv, &aad, &mut buffer, &tag)
            .expect("the tag this suite just produced verifies");
        assert_eq!(hex(&buffer), hex(&plaintext));
    }

    // RFC 7714 §17.2: SRTCP AEAD_AES_256_GCM, verification and decryption.
    #[test]
    fn rfc_7714_17_2_srtcp_aead_256_gcm_decryption() {
        let key: [u8; 32] =
            unhexn("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv: [u8; SALT] = unhexn(RTCP_IV);
        let aad = unhex(RTCP_AAD_ENCRYPTED);
        let mut buffer = unhex(
            "d50ae4d1f5ce5d304ba297e47d470c282c3ece5dbffe0a50a2eaa5c1110555be8415f658c61de0\
             476f1b6fad",
        );
        let tag: [u8; TAG] = unhexn("1d1eb30c4446839f57ff6f6cb26ac3be");
        let plaintext = unhex(RTCP_PT);

        Gcm::new(&key)
            .open(&iv, &aad, &mut buffer, &tag)
            .expect("the received tag verifies");
        assert_eq!(hex(&buffer), hex(&plaintext));
    }

    // RFC 7714 §17.3: SRTCP AEAD_AES_128_GCM, tagged but not encrypted.
    #[test]
    fn rfc_7714_17_3_srtcp_aead_128_gcm_tagging_only() {
        let key: [u8; 16] = unhexn("000102030405060708090a0b0c0d0e0f");
        let iv: [u8; SALT] = unhexn(RTCP_IV);
        let aad = unhex(RTCP_WHOLE_AS_AAD);

        let cipher = Gcm::new(&key);
        let mut empty: [u8; 0] = [];
        let tag = cipher
            .seal(&iv, &aad, &mut empty)
            .expect("well within the length bound");
        assert_eq!(hex(&tag), "841dd9683dd78ec92ae58790125f62b3");
        cipher
            .open(&iv, &aad, &mut empty, &tag)
            .expect("the tag this suite just produced verifies");
    }

    // RFC 7714 §17.4: SRTCP AEAD_AES_256_GCM, tag verification only.
    #[test]
    fn rfc_7714_17_4_srtcp_aead_256_gcm_tag_verification() {
        let key: [u8; 32] =
            unhexn("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv: [u8; SALT] = unhexn(RTCP_IV);
        let aad = unhex(RTCP_WHOLE_AS_AAD);
        let tag: [u8; TAG] = unhexn("91db4afbfeee5a978fab4393ed2615fe");

        let mut empty: [u8; 0] = [];
        Gcm::new(&key)
            .open(&iv, &aad, &mut empty, &tag)
            .expect("the received tag verifies");
    }

    #[test]
    fn a_bit_flipped_in_the_tag_is_refused() {
        let key: [u8; 16] = unhexn("000102030405060708090a0b0c0d0e0f");
        let iv: [u8; SALT] = unhexn(RTP_IV);
        let aad = unhex(RTP_AAD);
        let cipher = Gcm::new(&key);
        let mut buffer = unhex(RTP_PT);
        let mut tag = cipher
            .seal(&iv, &aad, &mut buffer)
            .expect("well within the length bound");
        tag[0] ^= 0x01;
        assert!(cipher.open(&iv, &aad, &mut buffer, &tag).is_err());
    }

    #[test]
    fn a_bit_flipped_in_the_associated_data_is_refused() {
        let key: [u8; 16] = unhexn("000102030405060708090a0b0c0d0e0f");
        let iv: [u8; SALT] = unhexn(RTP_IV);
        let aad = unhex(RTP_AAD);
        let cipher = Gcm::new(&key);
        let mut buffer = unhex(RTP_PT);
        let tag = cipher
            .seal(&iv, &aad, &mut buffer)
            .expect("well within the length bound");
        let mut wrong_aad = aad;
        if let Some(byte) = wrong_aad.first_mut() {
            *byte ^= 0x01;
        }
        assert!(cipher.open(&iv, &wrong_aad, &mut buffer, &tag).is_err());
    }
}
