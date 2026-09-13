// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! AES-128-GCM record protection (RFC 5246 §6.2.3.3, RFC 5288 §3), with the
//! DTLS sequence number of RFC 6347 §4.1.2.1.

use core::fmt;

use aes_gcm::aead::{Nonce, Tag};
use aes_gcm::{AeadInOut, Aes128Gcm, KeyInit};
use zeroize::{Zeroize, Zeroizing};

use super::{
    ContentType, HEADER_LEN, MAX_PLAINTEXT_LEN, MAX_SEQUENCE, ProtocolVersion, Record,
    RecordHeader, check_fragment, epoch_and_sequence,
};
use crate::Error;
use crate::prf::{WRITE_IV_LEN, WRITE_KEY_LEN};

/// `SecurityParameters.record_iv_length`: the explicit nonce carried in each
/// record.
pub const EXPLICIT_NONCE_LEN: usize = 8;
/// The authentication tag: AEAD_AES_128_GCM's, 16 octets (RFC 5116 §5.1).
pub const TAG_LEN: usize = 16;
/// What protection adds to a fragment. Exact for this suite, which pads
/// nothing, and what a sender subtracts from the path MTU along with the
/// record header.
pub const GCM_OVERHEAD: usize = EXPLICIT_NONCE_LEN + TAG_LEN;

/// One direction's AES-128-GCM record protection: the write key and the
/// implicit part of the nonce.
///
/// The same value seals on the sending side and opens on the receiving side;
/// [`crate::prf::KeyBlock::protection`] makes the one for either direction.
/// The key schedule and the IV are wiped when this is dropped.
pub struct GcmProtection {
    cipher: Aes128Gcm,
    fixed_iv: Zeroizing<[u8; WRITE_IV_LEN]>,
}

impl GcmProtection {
    /// Protection under `write_key`, with `write_iv` as the salt of every nonce.
    #[must_use]
    pub fn new(write_key: &[u8; WRITE_KEY_LEN], write_iv: &[u8; WRITE_IV_LEN]) -> Self {
        let mut key = aes_gcm::Key::<Aes128Gcm>::from(*write_key);
        let cipher = Aes128Gcm::new(&key);
        key.as_mut_slice().zeroize();
        Self {
            cipher,
            fixed_iv: Zeroizing::new(*write_iv),
        }
    }

    /// Write `DTLSCiphertext` for `plaintext`: the header, then
    /// `GenericAEADCipher` — the explicit nonce, the ciphertext, the tag.
    ///
    /// The explicit nonce is the epoch and sequence number, the 64-bit value
    /// RFC 6347 §4.1.2.1 puts in place of TLS's sequence number. RFC 5288 §3
    /// allows exactly that ("the nonce_explicit MAY be the 64-bit sequence
    /// number") and requires only that it never repeat under one key, which
    /// holds as long as a sequence number is never reused in its epoch —
    /// [`super::WriteEpoch`] hands each out once.
    ///
    /// # Errors
    ///
    /// [`Error::TooLarge`] for more than 2^14 octets; [`Error::Length`] for an
    /// empty fragment of any type but application data;
    /// [`Error::SequenceExhausted`] for a sequence number wider than 48 bits.
    /// Nothing is written on error.
    pub fn seal(
        &self,
        content_type: ContentType,
        version: ProtocolVersion,
        epoch: u16,
        sequence: u64,
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        check_fragment(content_type, plaintext.len())?;
        if sequence > MAX_SEQUENCE {
            return Err(Error::SequenceExhausted);
        }
        let explicit = epoch_and_sequence(epoch, sequence);
        let nonce = self.nonce(explicit);
        let aad = additional_data(explicit, content_type, version, plaintext.len())?;
        let length = u16::try_from(plaintext.len() + GCM_OVERHEAD).map_err(|_| Error::TooLarge)?;

        let start = out.len();
        out.reserve(HEADER_LEN + GCM_OVERHEAD + plaintext.len());
        let header = RecordHeader {
            content_type,
            version,
            epoch,
            sequence,
            length,
        };
        header.encode(out)?;
        out.extend_from_slice(&explicit);
        let body = out.len();
        out.extend_from_slice(plaintext);
        let sealed = match out.get_mut(body..) {
            Some(buffer) => self
                .cipher
                .encrypt_inout_detached(&nonce, &aad, buffer.into())
                .map_err(|_| Error::TooLarge),
            None => Err(Error::TooLarge),
        };
        match sealed {
            Ok(tag) => {
                out.extend_from_slice(tag.as_slice());
                Ok(())
            }
            Err(error) => {
                out.truncate(start);
                Err(error)
            }
        }
    }

    /// Authenticate and decrypt a protected record, appending its plaintext to
    /// `out`.
    ///
    /// The nonce takes its explicit part from the record, as RFC 5246
    /// §6.2.3.3 has the receiver do; the additional data takes the epoch and
    /// sequence number from the record header. Run the replay check before
    /// this and accept the sequence number only after it succeeds (RFC 6347
    /// §4.1.2.6).
    ///
    /// # Errors
    ///
    /// [`Error::BadRecordMac`] for a fragment too short to hold a nonce and a
    /// tag, or one that does not authenticate — RFC 5288 §3 has every AES-GCM
    /// failure reported that way; [`Error::TooLarge`] when the plaintext would
    /// exceed 2^14 octets, found before any decryption is attempted. Nothing
    /// is appended on error.
    pub fn open(&self, record: &Record<'_>, out: &mut Vec<u8>) -> Result<(), Error> {
        let (explicit, rest) = record
            .fragment
            .split_first_chunk::<EXPLICIT_NONCE_LEN>()
            .ok_or(Error::BadRecordMac)?;
        let (ciphertext, tag) = rest
            .split_last_chunk::<TAG_LEN>()
            .ok_or(Error::BadRecordMac)?;
        if ciphertext.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::TooLarge);
        }
        let nonce = self.nonce(*explicit);
        let aad = additional_data(
            record.header.epoch_and_sequence(),
            record.header.content_type,
            record.header.version,
            ciphertext.len(),
        )?;
        let tag = Tag::<Aes128Gcm>::from(*tag);

        let start = out.len();
        out.extend_from_slice(ciphertext);
        let opened = match out.get_mut(start..) {
            Some(buffer) => self
                .cipher
                .decrypt_inout_detached(&nonce, &aad, buffer.into(), &tag)
                .map_err(|_| Error::BadRecordMac),
            None => Err(Error::BadRecordMac),
        };
        if opened.is_err() {
            out.truncate(start);
        }
        opened
    }

    /// `GCMNonce`: the four-octet salt from the key block, then the eight
    /// octets carried in the record (RFC 5288 §3).
    fn nonce(&self, explicit: [u8; EXPLICIT_NONCE_LEN]) -> Nonce<Aes128Gcm> {
        let mut nonce = [0u8; WRITE_IV_LEN + EXPLICIT_NONCE_LEN];
        for (slot, byte) in nonce.iter_mut().zip(self.fixed_iv.iter().chain(&explicit)) {
            *slot = *byte;
        }
        Nonce::<Aes128Gcm>::from(nonce)
    }
}

impl fmt::Debug for GcmProtection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GcmProtection").finish_non_exhaustive()
    }
}

/// `additional_data = seq_num + TLSCompressed.type + TLSCompressed.version +
/// TLSCompressed.length` (RFC 5246 §6.2.3.3), where DTLS's `seq_num` is the
/// epoch and sequence number and the length is the plaintext's.
fn additional_data(
    seq_num: [u8; 8],
    content_type: ContentType,
    version: ProtocolVersion,
    plaintext_len: usize,
) -> Result<[u8; 13], Error> {
    let [l0, l1] = u16::try_from(plaintext_len)
        .map_err(|_| Error::TooLarge)?
        .to_be_bytes();
    let [s0, s1, s2, s3, s4, s5, s6, s7] = seq_num;
    Ok([
        s0,
        s1,
        s2,
        s3,
        s4,
        s5,
        s6,
        s7,
        content_type.0,
        version.major,
        version.minor,
        l0,
        l1,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::MAX_CIPHERTEXT_LEN;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// One test from NIST's CAVP GCM vectors, `gcmEncryptExtIV128.rsp`.
    struct Vector {
        key: &'static str,
        iv: &'static str,
        plaintext: &'static str,
        aad: &'static str,
        ciphertext: &'static str,
        tag: &'static str,
    }

    // [Keylen = 128] [IVlen = 96] [PTlen = 408] [AADlen = 0] [Taglen = 128], Count = 0
    const WITHOUT_AAD: Vector = Vector {
        key: "594157ec4693202b030f33798b07176d", // gitleaks:allow (NIST CAVP test vector)
        iv: "49b12054082660803a1df3df",
        plaintext: "3feef98a976a1bd634f364ac428bb59cd51fb159ec1789946918dbd50ea6c9d594a3a31a5269b0da6936c29d063a5fa2cc8a1c",
        aad: "",
        ciphertext: "c1b7a46a335f23d65b8db4008a49796906e225474f4fe7d39e55bf2efd97fd82d4167de082ae30fa01e465a601235d8d68bc69",
        tag: "ba92d3661ce8b04687e8788d55417dc2",
    };

    // [Keylen = 128] [IVlen = 96] [PTlen = 408] [AADlen = 160] [Taglen = 128], Count = 0
    const WITH_AAD: Vector = Vector {
        key: "fe47fcce5fc32665d2ae399e4eec72ba", // gitleaks:allow (NIST CAVP test vector)
        iv: "5adb9609dbaeb58cbd6e7275",
        plaintext: "7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429bea063",
        aad: "88319d6e1d3ffa5f987199166c8a9b56c2aeba5a",
        ciphertext: "98f4826f05a265e6dd2be82db241c0fbbbf9ffb1c173aa83964b7cf5393043736365253ddbc5db8778371495da76d269e5db3e",
        tag: "291ef1982e4defedaa2249f898556b47",
    };

    fn nist_protection() -> GcmProtection {
        let key: [u8; 16] = hex(WITH_AAD.key).try_into().unwrap();
        // the first four octets of the vector's IV play the salt from the key block
        let salt: [u8; 4] = hex(WITH_AAD.iv)[..4].try_into().unwrap();
        GcmProtection::new(&key, &salt)
    }

    #[test]
    fn the_primitive_agrees_with_the_published_gcm_vectors() {
        for vector in [WITHOUT_AAD, WITH_AAD] {
            let key: [u8; 16] = hex(vector.key).try_into().unwrap();
            let iv: [u8; 12] = hex(vector.iv).try_into().unwrap();
            let mut buffer = hex(vector.plaintext);
            let tag = Aes128Gcm::new(&key.into())
                .encrypt_inout_detached(&iv.into(), &hex(vector.aad), buffer.as_mut_slice().into())
                .unwrap();
            assert_eq!(buffer, hex(vector.ciphertext), "{}", vector.key);
            assert_eq!(tag.to_vec(), hex(vector.tag), "{}", vector.key);
        }
    }

    #[test]
    fn the_nonce_is_the_salt_then_the_epoch_and_sequence_number_and_the_aad_is_rfc_5246s() {
        // epoch 0xdbae and sequence 0xb58cbd6e7275 make the explicit nonce
        // dbaeb58cbd6e7275, so salt + explicit nonce is the vector's IV and the
        // ciphertext must be the vector's, whatever the AAD. The AAD is not the
        // vector's, so the tag is recomputed from the formula written out here.
        let protection = nist_protection();
        let plaintext = hex(WITH_AAD.plaintext);
        assert_eq!(plaintext.len(), 51);
        let mut out = Vec::new();
        protection
            .seal(
                ContentType::APPLICATION_DATA,
                ProtocolVersion::DTLS_1_2,
                0xdbae,
                0xb58c_bd6e_7275,
                &plaintext,
                &mut out,
            )
            .unwrap();

        assert_eq!(
            out[..HEADER_LEN],
            [
                23,
                254,
                253,
                0xdb,
                0xae,
                0xb5,
                0x8c,
                0xbd,
                0x6e,
                0x72,
                0x75,
                0,
                51 + 24
            ]
        );
        assert_eq!(out[HEADER_LEN..HEADER_LEN + 8], hex(WITH_AAD.iv)[4..]);
        assert_eq!(
            out[HEADER_LEN + 8..HEADER_LEN + 8 + 51],
            hex(WITH_AAD.ciphertext)
        );

        let aad = [
            0xdb, 0xae, 0xb5, 0x8c, 0xbd, 0x6e, 0x72, 0x75, // seq_num: epoch + sequence
            23,   // type
            254, 253, // version
            0, 51, // plaintext length
        ];
        let key: [u8; 16] = hex(WITH_AAD.key).try_into().unwrap();
        let iv: [u8; 12] = hex(WITH_AAD.iv).try_into().unwrap();
        let mut buffer = plaintext.clone();
        let tag = Aes128Gcm::new(&key.into())
            .encrypt_inout_detached(&iv.into(), &aad, buffer.as_mut_slice().into())
            .unwrap();
        assert_eq!(out[HEADER_LEN + 8 + 51..], tag[..]);

        let (record, rest) = Record::parse(&out).unwrap();
        assert!(rest.is_empty());
        let mut opened = Vec::new();
        protection.open(&record, &mut opened).unwrap();
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn every_field_the_tag_covers_is_checked() {
        let protection = nist_protection();
        let mut sealed = Vec::new();
        protection
            .seal(
                ContentType::HANDSHAKE,
                ProtocolVersion::DTLS_1_2,
                1,
                5,
                b"finished",
                &mut sealed,
            )
            .unwrap();

        // every octet of the record: the header through the AAD, the explicit
        // nonce through the nonce, the ciphertext and tag directly. The length
        // field is the exception, since changing it changes where the record ends.
        for position in (0..sealed.len()).filter(|&p| p != 11 && p != 12) {
            let mut forged = sealed.clone();
            forged[position] ^= 0x01;
            let (record, _) = Record::parse(&forged).unwrap();
            let mut out = vec![0xEE];
            assert_eq!(
                protection.open(&record, &mut out),
                Err(Error::BadRecordMac),
                "octet {position}"
            );
            assert_eq!(out, [0xEE]);
        }
    }

    #[test]
    fn the_other_directions_keys_do_not_open_a_record() {
        let client = GcmProtection::new(&[1; 16], &[2; 4]);
        let same_key_other_iv = GcmProtection::new(&[1; 16], &[3; 4]);
        let mut sealed = Vec::new();
        client
            .seal(
                ContentType::APPLICATION_DATA,
                ProtocolVersion::DTLS_1_2,
                1,
                0,
                b"x",
                &mut sealed,
            )
            .unwrap();
        let (record, _) = Record::parse(&sealed).unwrap();
        assert_eq!(
            same_key_other_iv.open(&record, &mut Vec::new()),
            Err(Error::BadRecordMac)
        );
        let mut out = Vec::new();
        client.open(&record, &mut out).unwrap();
        assert_eq!(out, b"x");
    }

    #[test]
    fn a_fragment_too_short_for_nonce_and_tag_is_a_bad_mac() {
        let protection = nist_protection();
        for len in 0..GCM_OVERHEAD {
            let fragment = vec![0u8; len];
            let record = Record {
                header: RecordHeader {
                    content_type: ContentType::APPLICATION_DATA,
                    version: ProtocolVersion::DTLS_1_2,
                    epoch: 1,
                    sequence: 0,
                    length: u16::try_from(len).unwrap(),
                },
                fragment: &fragment,
            };
            assert_eq!(
                protection.open(&record, &mut Vec::new()),
                Err(Error::BadRecordMac)
            );
        }
    }

    #[test]
    fn the_size_limits_hold_in_both_directions() {
        let protection = nist_protection();
        let v = ProtocolVersion::DTLS_1_2;
        let mut out = Vec::new();
        protection
            .seal(
                ContentType::APPLICATION_DATA,
                v,
                1,
                0,
                &vec![7; MAX_PLAINTEXT_LEN],
                &mut out,
            )
            .unwrap();
        assert_eq!(out.len(), HEADER_LEN + MAX_PLAINTEXT_LEN + GCM_OVERHEAD);
        let mut refused = Vec::new();
        assert_eq!(
            protection.seal(
                ContentType::APPLICATION_DATA,
                v,
                1,
                1,
                &vec![7; MAX_PLAINTEXT_LEN + 1],
                &mut refused
            ),
            Err(Error::TooLarge)
        );
        assert_eq!(
            protection.seal(ContentType::HANDSHAKE, v, 1, 1, &[], &mut refused),
            Err(Error::Length)
        );
        assert_eq!(
            protection.seal(
                ContentType::HANDSHAKE,
                v,
                1,
                MAX_SEQUENCE + 1,
                b"x",
                &mut refused
            ),
            Err(Error::SequenceExhausted)
        );
        assert!(refused.is_empty());

        // a record inside the ciphertext limit whose plaintext would be over
        // 2^14 is refused before anything is decrypted
        let fragment = vec![0u8; MAX_PLAINTEXT_LEN + 1 + GCM_OVERHEAD];
        assert!(fragment.len() <= MAX_CIPHERTEXT_LEN);
        let record = Record {
            header: RecordHeader {
                content_type: ContentType::APPLICATION_DATA,
                version: v,
                epoch: 1,
                sequence: 0,
                length: u16::try_from(fragment.len()).unwrap(),
            },
            fragment: &fragment,
        };
        assert_eq!(
            protection.open(&record, &mut Vec::new()),
            Err(Error::TooLarge)
        );
    }

    #[test]
    fn protection_is_not_printed() {
        assert_eq!(format!("{:?}", nist_protection()), "GcmProtection { .. }");
    }
}
