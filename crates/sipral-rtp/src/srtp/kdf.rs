// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Session keys from a master key, per RFC 3711 §4.3.
//!
//! One master key and salt come from key management; six session values come
//! out of this, three for SRTP and three for SRTCP, each identified by a
//! one-octet label. The PRF is AES in counter mode over the master key
//! (§4.3.3), which is why this sits on top of `cipher`.

use zeroize::{Zeroize, Zeroizing};

use super::cipher::{self, Counter};

/// Master and session encryption key length, `n_e` (§5.1), for the suite
/// every implementation has. A caller that cares which suite it is reads the
/// length off [`super::Suite`] instead.
pub const KEY: usize = cipher::KEY_128;

/// Master and session salt length, `n_s` (§5.1): 112 bits, for AES-CM and
/// f8. RFC 7714's GCM suites use a 96-bit one instead (§8.1); see
/// [`super::Suite::salt_len`].
pub const SALT: usize = 14;

/// Session authentication key length, `n_a` (§5.2): 160 bits, which is
/// HMAC-SHA-1's block-independent natural key. AEAD suites derive none —
/// RFC 7714 §8.1: "AEAD algorithms do not require a separate authentication
/// key."
pub(crate) const AUTH: usize = 20;

/// The three lengths a suite hands the key derivation: `n_e`, `n_s`, and
/// whether an authentication key is derived at all.
///
/// Kept apart from [`super::Suite`] itself, the way [`cipher`] is kept apart
/// from the suites it serves: this module derives whatever lengths it is
/// asked for and does not need to know which suite asked.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Lengths {
    pub(crate) key: usize,
    pub(crate) salt: usize,
    pub(crate) auth: bool,
}

/// The labels of §4.3.1 and §4.3.2. The value is the octet on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Label {
    RtpEncryption = 0x00,
    RtpAuthentication = 0x01,
    RtpSalt = 0x02,
    RtcpEncryption = 0x03,
    RtcpAuthentication = 0x04,
    RtcpSalt = 0x05,
}

/// How often session keys are re-derived from the master key.
///
/// RFC 4568 §6.3.1 carries this as `KDR=n` meaning 2^n, with n from 1 to 24,
/// and an absent parameter meaning a single derivation for the whole session
/// — which is §4.3.1's `key_derivation_rate` of zero and the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rate(Option<u8>);

impl Rate {
    /// A single derivation, before the first packet, and no other.
    pub const ONCE: Self = Self(None);

    /// `2^exponent` packets between derivations. RFC 4568 §6.3.1 bounds the
    /// exponent to 1..=24; anything else is not a rate this can honour.
    #[must_use]
    pub fn from_exponent(exponent: u8) -> Option<Self> {
        (1..=24).contains(&exponent).then_some(Self(Some(exponent)))
    }

    /// `index DIV key_derivation_rate`, which §4.3.1 defines as zero for a
    /// rate of zero and otherwise as a right shift.
    pub(crate) fn phase_of(self, index: u64) -> u64 {
        match self.0 {
            None => 0,
            Some(exponent) => index >> u32::from(exponent),
        }
    }

    /// Whether a packet at this index starts a new derivation.
    #[must_use]
    pub fn refreshes_at(self, index: u64) -> bool {
        match self.0 {
            None => index == 0,
            Some(exponent) => index & ((1_u64 << exponent) - 1) == 0,
        }
    }
}

/// The master key and salt a key management protocol hands over.
///
/// The length of each is whatever the suite calls for — sixteen or
/// thirty-two octets of key, twelve or fourteen of salt — so this holds them
/// as grown rather than as one of the fixed shapes; [`Zeroizing`] wipes each
/// on drop exactly as the fixed arrays did.
pub struct Master {
    key: Zeroizing<Vec<u8>>,
    salt: Zeroizing<Vec<u8>>,
}

/// One direction's session keys, for either SRTP or SRTCP.
///
/// `authentication` is `None` for an AEAD suite, which derives no separate
/// authentication key (RFC 7714 §8.1).
pub(crate) struct Session {
    pub(crate) encryption: Zeroizing<Vec<u8>>,
    pub(crate) salt: Zeroizing<Vec<u8>>,
    pub(crate) authentication: Option<Zeroizing<[u8; AUTH]>>,
}

impl Master {
    /// The key and salt a key management protocol produced, each the width
    /// the suite calls for. For SDES that is the base64 payload of an
    /// `inline:` parameter, split at the suite's own key length (RFC 4568
    /// §6.1, RFC 7714 §14.1).
    #[must_use]
    pub fn new(key: &[u8], salt: &[u8]) -> Self {
        Self {
            key: Zeroizing::new(key.to_vec()),
            salt: Zeroizing::new(salt.to_vec()),
        }
    }

    /// The three SRTP session values for the packet index `index`.
    pub(crate) fn rtp_session(&self, rate: Rate, index: u64, lengths: Lengths) -> Session {
        self.session(
            rate,
            index,
            lengths,
            Label::RtpEncryption,
            Label::RtpAuthentication,
            Label::RtpSalt,
        )
    }

    /// The three SRTCP session values.
    ///
    /// §4.3.2 replaces the packet index with the SRTCP index. It says the
    /// substitute is 32 bits wide, which would move the label two octets to
    /// the right of where SRTP puts it; erratum 3712 corrects that to 48 bits
    /// so the two land in the same octet, and notes that implementations do
    /// it the corrected way. Interoperating matters more than the printed
    /// text, and here they agree once the erratum is applied.
    pub(crate) fn rtcp_session(&self, rate: Rate, index: u32, lengths: Lengths) -> Session {
        self.session(
            rate,
            u64::from(index),
            lengths,
            Label::RtcpEncryption,
            Label::RtcpAuthentication,
            Label::RtcpSalt,
        )
    }

    fn session(
        &self,
        rate: Rate,
        index: u64,
        lengths: Lengths,
        encryption: Label,
        authentication: Label,
        salt: Label,
    ) -> Session {
        let phase = rate.phase_of(index);
        let mut encryption_key = vec![0_u8; lengths.key];
        let mut salt_key = vec![0_u8; lengths.salt];
        self.prf(encryption, phase, lengths.salt, &mut encryption_key);
        self.prf(salt, phase, lengths.salt, &mut salt_key);
        let authentication_key = lengths.auth.then(|| {
            let mut key = [0_u8; AUTH];
            self.prf(authentication, phase, lengths.salt, &mut key);
            Zeroizing::new(key)
        });
        Session {
            encryption: Zeroizing::new(encryption_key),
            salt: Zeroizing::new(salt_key),
            authentication: authentication_key,
        }
    }

    /// `PRF_n(k_master, x)` where `x = (<label> || r) XOR master_salt`, and
    /// the counter-mode IV is `x * 2^16` (§4.3.3).
    ///
    /// `salt_len` is the crypto context's own `n_s`: fourteen octets for
    /// AES-CM and f8, twelve for RFC 7714's GCM suites. The PRF is defined
    /// over RFC 3711's 112-bit salt, and §4.3.1 aligns `key_id` with it "so
    /// that their least significant bits agree": `key_id` is seven octets
    /// wide whatever the suite, since the packet index is 48 bits, and sits
    /// at octets seven to fourteen, the `*2^16` step leaving the last two of
    /// the sixteen-octet block zero. RFC 7714 §11 runs its GCM suites through
    /// that same PRF and says nothing about widening their 96-bit salt to
    /// it; the SRTP stacks a call meets widen it with two zero octets on the
    /// right, so the salt starts at octet zero whatever its width, and the
    /// fourteen-octet one lands exactly where §4.3.1 puts it either way.
    fn prf(&self, label: Label, phase: u64, salt_len: usize, out: &mut [u8]) {
        debug_assert_eq!(
            self.salt.len(),
            salt_len,
            "the master salt is always exactly as wide as the suite it is used with"
        );
        let mut iv = [0_u8; cipher::BLOCK];
        if let Some(head) = iv.get_mut(..salt_len.min(cipher::BLOCK - 2)) {
            head.copy_from_slice(self.salt.get(..head.len()).unwrap_or_default());
        }

        // key_id is the label followed by the six octets of the phase
        let mut key_id = [0_u8; 7];
        if let Some(first) = key_id.first_mut() {
            *first = label as u8;
        }
        if let Some(tail) = key_id.get_mut(1..) {
            tail.copy_from_slice(phase.to_be_bytes().get(2..).unwrap_or_default());
        }
        for (byte, id) in iv
            .iter_mut()
            .skip(cipher::BLOCK - 2 - key_id.len())
            .zip(key_id)
        {
            *byte ^= id;
        }

        out.fill(0);
        // the output is at most a few hundred octets, far inside the 2^16
        // blocks a single IV allows, so this cannot report exhaustion
        let _ = Counter::new(&self.key).apply(&iv, out);
        iv.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::super::testing::{hex, unhex};
    use super::{AUTH, KEY, Label, Lengths, Master, Rate, SALT};

    /// The lengths of the suite every implementation has: AES-128, a
    /// fourteen-octet salt, and an authentication key.
    const CM_80: Lengths = Lengths {
        key: KEY,
        salt: SALT,
        auth: true,
    };

    fn appendix_b3() -> Master {
        let key = unhex("e1f97a0d3e018be0d64fa32c06de4139");
        let salt = unhex("0ec675ad498afeebb6960b3aabe6");
        Master::new(&key, &salt)
    }

    // RFC 3711 Appendix B.3
    #[test]
    fn appendix_b3_cipher_key_and_salt() {
        let keys = appendix_b3().rtp_session(Rate::ONCE, 0, CM_80);
        assert_eq!(hex(&keys.encryption), "c61e7a93744f39ee10734afe3ff7a087");
        assert_eq!(hex(&keys.salt), "30cbbc08863d8c85d49db34a9ae1");
    }

    // the appendix walks 94 octets of authentication key, which is six AES
    // blocks; the session only needs the first twenty, but running the PRF
    // out to the end is what proves the counter advances correctly
    #[test]
    fn appendix_b3_authentication_key() {
        let master = appendix_b3();
        let mut long = [0_u8; 94];
        master.prf(Label::RtpAuthentication, 0, SALT, &mut long);
        assert_eq!(
            hex(&long),
            "cebe321f6ff7716b6fd4ab49af256a15\
             6d38baa48f0a0acf3c34e2359e6cdbce\
             e049646c43d9327ad175578ef7227098\
             6371c10c9a369ac2f94a8c5fbcdddc25\
             6d6e919a48b610ef17c2041e47403576\
             6b68642c59bbfc2f34db60dbdfb2"
        );

        let keys = master.rtp_session(Rate::ONCE, 0, CM_80);
        let authentication = keys.authentication.expect("this suite derives one");
        assert_eq!(
            hex(&*authentication),
            hex(long.get(..AUTH).unwrap_or_default())
        );
    }

    #[test]
    fn an_aead_suite_derives_no_authentication_key() {
        // a master salt of the AEAD suites' own twelve octets, since a real
        // one never carries fourteen for a suite whose n_s is twelve
        let master = Master::new(
            &unhex("e1f97a0d3e018be0d64fa32c06de4139"),
            &unhex("0ec675ad498afeebb6960b3aa"),
        );
        let lengths = Lengths {
            key: 16,
            salt: 12,
            auth: false,
        };
        let keys = master.rtp_session(Rate::ONCE, 0, lengths);
        assert!(keys.authentication.is_none());
        assert_eq!(keys.encryption.len(), 16);
        assert_eq!(keys.salt.len(), 12);
    }

    /// A GCM suite's 96-bit master salt goes through RFC 3711's 112-bit PRF
    /// as that salt with two zero octets after it, which is how the SRTP
    /// stacks a call meets widen it: the keys it derives are the ones a
    /// fourteen-octet salt ending in two zeros derives, both the session key
    /// and the twelve octets of session salt, for SRTP and SRTCP alike and
    /// at a later derivation too. Right-aligned instead, every packet either
    /// end protects fails the other's tag check.
    #[test]
    fn a_twelve_octet_salt_derives_what_it_does_padded_with_two_zeros() {
        let key = unhex("e1f97a0d3e018be0d64fa32c06de4139");
        let salt = unhex("0ec675ad498afeebb6960b3a");
        assert_eq!(salt.len(), 12);
        let mut padded = salt.clone();
        padded.extend_from_slice(&[0, 0]);
        let aead = Lengths {
            key: 16,
            salt: 12,
            auth: false,
        };
        let widened = Lengths {
            key: 16,
            salt: 14,
            auth: false,
        };
        let short = Master::new(&key, &salt);
        let long = Master::new(&key, &padded);
        let rate = Rate::from_exponent(4).expect("a rate");
        for index in [0_u64, 16, 1 << 20] {
            let (media, media_long) = (
                short.rtp_session(rate, index, aead),
                long.rtp_session(rate, index, widened),
            );
            assert_eq!(hex(&media.encryption), hex(&media_long.encryption));
            assert_eq!(
                hex(&media.salt),
                hex(media_long.salt.get(..12).unwrap_or_default())
            );
            let (control, control_long) = (
                short.rtcp_session(rate, 7, aead),
                long.rtcp_session(rate, 7, widened),
            );
            assert_eq!(hex(&control.encryption), hex(&control_long.encryption));
            assert_eq!(
                hex(&control.salt),
                hex(control_long.salt.get(..12).unwrap_or_default())
            );
        }
    }

    #[test]
    fn the_six_labels_give_six_different_keys() {
        let master = appendix_b3();
        let media = master.rtp_session(Rate::ONCE, 0, CM_80);
        let control = master.rtcp_session(Rate::ONCE, 0, CM_80);
        assert_ne!(media.encryption, control.encryption);
        assert_ne!(media.salt, control.salt);
        assert_ne!(media.authentication, control.authentication);
        assert_ne!(media.encryption, media.salt);
    }

    // erratum 3712: the SRTCP index is padded to 48 bits, so an SRTCP
    // derivation at index 0 differs from an SRTP one only by the label octet
    #[test]
    fn the_label_sits_in_the_same_octet_for_both() {
        let master = appendix_b3();
        let mut media_iv = [0_u8; 16];
        let mut control_iv = [0_u8; 16];
        master.prf(Label::RtpEncryption, 0, SALT, &mut media_iv);
        master.prf(Label::RtcpEncryption, 0, SALT, &mut control_iv);

        // derive the two by hand from salts that differ in exactly the octet
        // the labels occupy, and check the PRF agrees
        let mut shifted = appendix_b3();
        if let Some(byte) = shifted.salt.get_mut(SALT - 7) {
            *byte ^= 0x03;
        }
        let mut expected = [0_u8; 16];
        shifted.prf(Label::RtpEncryption, 0, SALT, &mut expected);
        assert_eq!(expected, control_iv);
        assert_ne!(media_iv, control_iv);
    }

    #[test]
    fn a_rate_of_once_never_refreshes_again() {
        assert!(Rate::ONCE.refreshes_at(0));
        assert!(!Rate::ONCE.refreshes_at(1));
        assert!(!Rate::ONCE.refreshes_at(1 << 40));
        let master = appendix_b3();
        let first = master.rtp_session(Rate::ONCE, 0, CM_80);
        let later = master.rtp_session(Rate::ONCE, 1_000_000, CM_80);
        assert_eq!(first.encryption, later.encryption);
    }

    #[test]
    fn a_rate_changes_the_keys_on_its_own_boundary() {
        let rate = Rate::from_exponent(10).expect("in range");
        let master = appendix_b3();
        let before = master.rtp_session(rate, 1023, CM_80);
        let after = master.rtp_session(rate, 1024, CM_80);
        assert_ne!(before.encryption, after.encryption);
        assert_eq!(
            before.encryption,
            master.rtp_session(rate, 0, CM_80).encryption,
            "everything below the boundary shares one derivation"
        );
        assert!(rate.refreshes_at(1024));
        assert!(!rate.refreshes_at(1025));
    }

    #[test]
    fn the_rate_exponent_is_bounded_the_way_rfc_4568_bounds_it() {
        assert!(Rate::from_exponent(0).is_none());
        assert!(Rate::from_exponent(1).is_some());
        assert!(Rate::from_exponent(24).is_some());
        assert!(Rate::from_exponent(25).is_none());
    }

    // RFC 6188 §7.2: the AES_256_CM_PRF key derivation, with a thirty-two
    // octet master key and the same fourteen-octet salt AES-CM uses.
    #[test]
    fn rfc_6188_aes_256_cm_prf() {
        let key = unhex("f0f04914b513f2763a1b1fa130f10e2998f6f6e43e4309d1e622a0e332b9f1b6");
        let salt = unhex("3b04803de51ee7c96423ab5b78d2");
        assert_eq!(key.len(), 32);
        assert_eq!(salt.len(), 14);
        let master = Master::new(&key, &salt);
        let keys = master.rtp_session(
            Rate::ONCE,
            0,
            Lengths {
                key: 32,
                salt: 14,
                auth: true,
            },
        );
        assert_eq!(
            hex(&keys.encryption),
            "5ba1064e30ec51613cad926c5a28ef731ec7fb397f70a960653caf06554cd8c4"
        );
        assert_eq!(hex(&keys.salt), "fa31791685ca444a9e07c6c64e93");
        assert_eq!(
            hex(&*keys.authentication.expect("this suite derives one")),
            "fd9c32d39ed5fbb5a9dc96b30818454d1313dc05"
        );
    }
}
