// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Session keys from a master key, per RFC 3711 §4.3.
//!
//! One master key and salt come from key management; six session values come
//! out of this, three for SRTP and three for SRTCP, each identified by a
//! one-octet label. The PRF is AES in counter mode over the master key
//! (§4.3.3), which is why this sits on top of `cipher`.

use zeroize::Zeroize;

use super::cipher::{self, Counter};

/// Master and session encryption key length, `n_e` (§5.1).
pub const KEY: usize = cipher::KEY;

/// Master and session salt length, `n_s` (§5.1): 112 bits.
pub const SALT: usize = 14;

/// Session authentication key length, `n_a` (§5.2): 160 bits, which is
/// HMAC-SHA-1's block-independent natural key.
pub(crate) const AUTH: usize = 20;

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
pub struct Master {
    key: [u8; KEY],
    salt: [u8; SALT],
}

impl Drop for Master {
    fn drop(&mut self) {
        self.key.zeroize();
        self.salt.zeroize();
    }
}

/// One direction's session keys, for either SRTP or SRTCP.
pub(crate) struct Session {
    pub(crate) encryption: [u8; KEY],
    pub(crate) salt: [u8; SALT],
    pub(crate) authentication: [u8; AUTH],
}

impl Drop for Session {
    fn drop(&mut self) {
        self.encryption.zeroize();
        self.salt.zeroize();
        self.authentication.zeroize();
    }
}

impl Master {
    /// The key and salt a key management protocol produced. For SDES that is
    /// the base64 payload of an `inline:` parameter, split at sixteen octets
    /// (RFC 4568 §6.1).
    #[must_use]
    pub const fn new(key: [u8; KEY], salt: [u8; SALT]) -> Self {
        Self { key, salt }
    }

    /// The three SRTP session values for the packet index `index`.
    pub(crate) fn rtp_session(&self, rate: Rate, index: u64) -> Session {
        self.session(
            rate,
            index,
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
    pub(crate) fn rtcp_session(&self, rate: Rate, index: u32) -> Session {
        self.session(
            rate,
            u64::from(index),
            Label::RtcpEncryption,
            Label::RtcpAuthentication,
            Label::RtcpSalt,
        )
    }

    fn session(
        &self,
        rate: Rate,
        index: u64,
        encryption: Label,
        authentication: Label,
        salt: Label,
    ) -> Session {
        let phase = rate.phase_of(index);
        let mut keys = Session {
            encryption: [0; KEY],
            salt: [0; SALT],
            authentication: [0; AUTH],
        };
        self.prf(encryption, phase, &mut keys.encryption);
        self.prf(authentication, phase, &mut keys.authentication);
        self.prf(salt, phase, &mut keys.salt);
        keys
    }

    /// `PRF_n(k_master, x)` where `x = (<label> || r) XOR master_salt`,
    /// right-aligned, and the counter-mode IV is `x * 2^16` (§4.3.3).
    fn prf(&self, label: Label, phase: u64, out: &mut [u8]) {
        let mut iv = [0_u8; cipher::BLOCK];
        if let Some(head) = iv.get_mut(..SALT) {
            head.copy_from_slice(&self.salt);
        }

        // key_id is the label followed by the six octets of the phase, and
        // its least significant bit lines up with the salt's
        let mut key_id = [0_u8; 7];
        if let Some(first) = key_id.first_mut() {
            *first = label as u8;
        }
        if let Some(tail) = key_id.get_mut(1..) {
            tail.copy_from_slice(phase.to_be_bytes().get(2..).unwrap_or_default());
        }
        for (byte, id) in iv.iter_mut().skip(SALT - key_id.len()).zip(key_id) {
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
    use super::{AUTH, KEY, Label, Master, Rate, SALT};

    fn appendix_b3() -> Master {
        let mut key = [0_u8; KEY];
        let mut salt = [0_u8; SALT];
        key.copy_from_slice(&unhex("e1f97a0d3e018be0d64fa32c06de4139"));
        salt.copy_from_slice(&unhex("0ec675ad498afeebb6960b3aabe6"));
        Master::new(key, salt)
    }

    // RFC 3711 Appendix B.3
    #[test]
    fn appendix_b3_cipher_key_and_salt() {
        let keys = appendix_b3().rtp_session(Rate::ONCE, 0);
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
        master.prf(Label::RtpAuthentication, 0, &mut long);
        assert_eq!(
            hex(&long),
            "cebe321f6ff7716b6fd4ab49af256a15\
             6d38baa48f0a0acf3c34e2359e6cdbce\
             e049646c43d9327ad175578ef7227098\
             6371c10c9a369ac2f94a8c5fbcdddc25\
             6d6e919a48b610ef17c2041e47403576\
             6b68642c59bbfc2f34db60dbdfb2"
        );

        let keys = master.rtp_session(Rate::ONCE, 0);
        assert_eq!(
            hex(&keys.authentication),
            hex(long.get(..AUTH).unwrap_or_default())
        );
    }

    #[test]
    fn the_six_labels_give_six_different_keys() {
        let master = appendix_b3();
        let media = master.rtp_session(Rate::ONCE, 0);
        let control = master.rtcp_session(Rate::ONCE, 0);
        assert_ne!(media.encryption, control.encryption);
        assert_ne!(media.salt, control.salt);
        assert_ne!(media.authentication, control.authentication);
        assert_ne!(media.encryption[..], media.salt[..]);
    }

    // erratum 3712: the SRTCP index is padded to 48 bits, so an SRTCP
    // derivation at index 0 differs from an SRTP one only by the label octet
    #[test]
    fn the_label_sits_in_the_same_octet_for_both() {
        let master = appendix_b3();
        let mut media_iv = [0_u8; 16];
        let mut control_iv = [0_u8; 16];
        master.prf(Label::RtpEncryption, 0, &mut media_iv);
        master.prf(Label::RtcpEncryption, 0, &mut control_iv);

        // derive the two by hand from salts that differ in exactly the octet
        // the labels occupy, and check the PRF agrees
        let mut shifted = appendix_b3();
        if let Some(byte) = shifted.salt.get_mut(SALT - 7) {
            *byte ^= 0x03;
        }
        let mut expected = [0_u8; 16];
        shifted.prf(Label::RtpEncryption, 0, &mut expected);
        assert_eq!(expected, control_iv);
        assert_ne!(media_iv, control_iv);
    }

    #[test]
    fn a_rate_of_once_never_refreshes_again() {
        assert!(Rate::ONCE.refreshes_at(0));
        assert!(!Rate::ONCE.refreshes_at(1));
        assert!(!Rate::ONCE.refreshes_at(1 << 40));
        let master = appendix_b3();
        let first = master.rtp_session(Rate::ONCE, 0);
        let later = master.rtp_session(Rate::ONCE, 1_000_000);
        assert_eq!(first.encryption, later.encryption);
    }

    #[test]
    fn a_rate_changes_the_keys_on_its_own_boundary() {
        let rate = Rate::from_exponent(10).expect("in range");
        let master = appendix_b3();
        let before = master.rtp_session(rate, 1023);
        let after = master.rtp_session(rate, 1024);
        assert_ne!(before.encryption, after.encryption);
        assert_eq!(
            before.encryption,
            master.rtp_session(rate, 0).encryption,
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
}
