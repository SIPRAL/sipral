// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Keying material exporters (RFC 5705), and the SRTP keys DTLS-SRTP takes
//! out of one (RFC 5764 §4.2).

use core::fmt;

use zeroize::Zeroizing;

use crate::handshake::SrtpProtectionProfile;
use crate::prf::{self, Derivation, HANDSHAKE_LABELS, MasterSecret};
use crate::{Error, Role};

/// RFC 5764 §4.2: "The exporter label for this usage is
/// "EXTRACTOR-dtls_srtp"."
pub const DTLS_SRTP_LABEL: &[u8] = b"EXTRACTOR-dtls_srtp";
/// `master_key_len` of both AES-128 counter-mode profiles: 128 bits.
pub const SRTP_MASTER_KEY_LEN: usize = 16;
/// `master_salt_len` of both AES-128 counter-mode profiles: 112 bits.
pub const SRTP_MASTER_SALT_LEN: usize = 14;

impl MasterSecret {
    /// Keying material exported under `label` (RFC 5705 §4):
    ///
    /// ```text
    /// PRF(master_secret, label, client_random + server_random)[length]
    /// PRF(master_secret, label, client_random + server_random +
    ///     context_value_length + context_value)[length]
    /// ```
    ///
    /// the first when `context` is `None`, the second when it is `Some` — an
    /// empty context still writes its two-octet length, so `Some(&[])` and
    /// `None` export different values, as the RFC's two formulas do.
    ///
    /// # Errors
    ///
    /// - [`Error::NoExtendedMasterSecret`] for a master secret made without
    ///   the extended master secret: RFC 7627 §5.4 requires such a session to
    ///   "disable \[RFC5705\]".
    /// - [`Error::ReservedLabel`] for a label the PRF already uses inside the
    ///   handshake. RFC 5705 §4 only recommends an "EXPORTER" prefix, since
    ///   existing labels (DTLS-SRTP's among them) lack it; refusing the exact
    ///   collisions is what keeps an exporter from handing out a
    ///   `verify_data` or a record key.
    /// - [`Error::Length`] for a context of 2^16 octets or more, which its
    ///   `uint16` length cannot describe.
    pub fn export(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), Error> {
        self.check_export(label)?;
        match context {
            None => prf::prf(
                self.secret(),
                label,
                &[self.client_random(), self.server_random()],
                out,
            ),
            Some(context) => {
                let length = u16::try_from(context.len())
                    .map_err(|_| Error::Length)?
                    .to_be_bytes();
                prf::prf(
                    self.secret(),
                    label,
                    &[self.client_random(), self.server_random(), &length, context],
                    out,
                );
            }
        }
        Ok(())
    }

    /// The SRTP master keys and salts for `profile` (RFC 5764 §4.2): an export
    /// under [`DTLS_SRTP_LABEL`] with no context, laid out as
    ///
    /// ```text
    /// client_write_SRTP_master_key[master_key_len]
    /// server_write_SRTP_master_key[master_key_len]
    /// client_write_SRTP_master_salt[master_salt_len]
    /// server_write_SRTP_master_salt[master_salt_len]
    /// ```
    ///
    /// The layout interleaves by kind, not by direction: both keys, then both
    /// salts.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] for any profile but the two AES-128 counter-mode
    /// ones — the NULL profiles are forbidden by RFC 8827 §6.5 and nothing
    /// else is defined — and the errors of [`MasterSecret::export`].
    pub fn srtp_keys(&self, profile: SrtpProtectionProfile) -> Result<SrtpKeys, Error> {
        if profile != SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80
            && profile != SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32
        {
            return Err(Error::IllegalValue);
        }
        self.check_export(DTLS_SRTP_LABEL)?;
        let mut keys = SrtpKeys {
            profile,
            client_key: Zeroizing::new([0; SRTP_MASTER_KEY_LEN]),
            server_key: Zeroizing::new([0; SRTP_MASTER_KEY_LEN]),
            client_salt: Zeroizing::new([0; SRTP_MASTER_SALT_LEN]),
            server_salt: Zeroizing::new([0; SRTP_MASTER_SALT_LEN]),
        };
        prf::prf_fields(
            self.secret(),
            DTLS_SRTP_LABEL,
            &[self.client_random(), self.server_random()],
            &mut [
                keys.client_key.as_mut_slice(),
                keys.server_key.as_mut_slice(),
                keys.client_salt.as_mut_slice(),
                keys.server_salt.as_mut_slice(),
            ],
        );
        Ok(keys)
    }

    fn check_export(&self, label: &[u8]) -> Result<(), Error> {
        if self.derivation() != Derivation::Extended {
            return Err(Error::NoExtendedMasterSecret);
        }
        if HANDSHAKE_LABELS.contains(&label) {
            return Err(Error::ReservedLabel);
        }
        Ok(())
    }
}

/// The SRTP master keys and salts of one DTLS-SRTP session.
///
/// RFC 5764 §4.2: the client's key and salt feed "one invocation of the SRTP
/// key derivation function, to generate the SRTP keys used to encrypt and
/// authenticate packets sent by the client", and the server "MUST only use
/// these keys to decrypt and to check the authenticity of inbound packets";
/// the server's the other way round. An MKI, when one was agreed, is carried
/// beside these and plays no part in deriving them.
///
/// Wiped when dropped, and never printed.
pub struct SrtpKeys {
    profile: SrtpProtectionProfile,
    client_key: Zeroizing<[u8; SRTP_MASTER_KEY_LEN]>,
    server_key: Zeroizing<[u8; SRTP_MASTER_KEY_LEN]>,
    client_salt: Zeroizing<[u8; SRTP_MASTER_SALT_LEN]>,
    server_salt: Zeroizing<[u8; SRTP_MASTER_SALT_LEN]>,
}

impl SrtpKeys {
    /// The profile the keys were exported for.
    #[must_use]
    pub const fn profile(&self) -> SrtpProtectionProfile {
        self.profile
    }

    /// The master key protecting what `writer` sends.
    #[must_use]
    pub fn master_key(&self, writer: Role) -> &[u8; SRTP_MASTER_KEY_LEN] {
        match writer {
            Role::Client => &self.client_key,
            Role::Server => &self.server_key,
        }
    }

    /// The master salt protecting what `writer` sends.
    #[must_use]
    pub fn master_salt(&self, writer: Role) -> &[u8; SRTP_MASTER_SALT_LEN] {
        match writer {
            Role::Client => &self.client_salt,
            Role::Server => &self.server_salt,
        }
    }
}

impl fmt::Debug for SrtpKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtpKeys")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prf::tests::p_sha256;

    const CLIENT_RANDOM: [u8; 32] = [0xC1; 32];
    const SERVER_RANDOM: [u8; 32] = [0x5E; 32];

    fn master() -> MasterSecret {
        MasterSecret::extended(&[0x0A; 32], &[0x33; 32], CLIENT_RANDOM, SERVER_RANDOM)
    }

    fn seed(label: &[u8], tail: &[&[u8]]) -> Vec<u8> {
        let mut seed = label.to_vec();
        seed.extend_from_slice(&CLIENT_RANDOM);
        seed.extend_from_slice(&SERVER_RANDOM);
        for piece in tail {
            seed.extend_from_slice(piece);
        }
        seed
    }

    #[test]
    fn an_export_is_the_prf_over_both_randoms_and_the_context_rfc_5705_describes() {
        let master = master();
        let label = b"EXPORTER-sipral-test";

        let mut none = [0u8; 50];
        master.export(label, None, &mut none).unwrap();
        assert_eq!(
            none.to_vec(),
            p_sha256(master.secret(), &seed(label, &[]), 50)
        );

        let context = b"a context";
        let mut some = [0u8; 50];
        master.export(label, Some(context), &mut some).unwrap();
        assert_eq!(
            some.to_vec(),
            p_sha256(master.secret(), &seed(label, &[&[0, 9], context]), 50)
        );

        let mut empty = [0u8; 50];
        master.export(label, Some(&[]), &mut empty).unwrap();
        assert_eq!(
            empty.to_vec(),
            p_sha256(master.secret(), &seed(label, &[&[0, 0]]), 50)
        );
        assert_ne!(empty, none);
    }

    #[test]
    fn the_srtp_keys_are_laid_out_as_rfc_5764_lays_them_out() {
        let master = master();
        let material = p_sha256(master.secret(), &seed(b"EXTRACTOR-dtls_srtp", &[]), 60);
        for profile in [
            SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
            SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
        ] {
            let keys = master.srtp_keys(profile).unwrap();
            assert_eq!(keys.profile(), profile);
            assert_eq!(keys.master_key(Role::Client)[..], material[0..16]);
            assert_eq!(keys.master_key(Role::Server)[..], material[16..32]);
            assert_eq!(keys.master_salt(Role::Client)[..], material[32..46]);
            assert_eq!(keys.master_salt(Role::Server)[..], material[46..60]);
        }
        let mut exported = [0u8; 60];
        master.export(DTLS_SRTP_LABEL, None, &mut exported).unwrap();
        assert_eq!(exported.to_vec(), material);
    }

    #[test]
    fn nothing_is_exported_from_a_legacy_master_secret() {
        let legacy = MasterSecret::legacy(&[0x0A; 32], CLIENT_RANDOM, SERVER_RANDOM);
        let mut out = [0u8; 16];
        assert_eq!(
            legacy.export(b"EXPORTER-x", None, &mut out),
            Err(Error::NoExtendedMasterSecret)
        );
        assert_eq!(out, [0; 16]);
        assert_eq!(
            legacy
                .srtp_keys(SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80)
                .err(),
            Some(Error::NoExtendedMasterSecret)
        );
    }

    #[test]
    fn a_label_the_handshake_uses_cannot_be_exported_under() {
        let master = master();
        let mut out = [0u8; 12];
        for label in [
            &b"master secret"[..],
            b"extended master secret",
            b"key expansion",
            b"client finished",
            b"server finished",
        ] {
            assert_eq!(
                master.export(label, None, &mut out),
                Err(Error::ReservedLabel)
            );
        }
        assert_eq!(master.export(b"client finished ", None, &mut out), Ok(()));
    }

    #[test]
    fn a_context_too_long_for_its_length_field_is_refused() {
        let master = master();
        let long = vec![0u8; 1 << 16];
        assert_eq!(
            master.export(b"EXPORTER-x", Some(&long), &mut [0u8; 4]),
            Err(Error::Length)
        );
        assert_eq!(
            master.export(b"EXPORTER-x", Some(&long[1..]), &mut [0u8; 4]),
            Ok(())
        );
    }

    #[test]
    fn only_the_aes_profiles_have_keys() {
        let master = master();
        for profile in [
            SrtpProtectionProfile::NULL_HMAC_SHA1_80,
            SrtpProtectionProfile::NULL_HMAC_SHA1_32,
            SrtpProtectionProfile(0x0007),
        ] {
            assert_eq!(master.srtp_keys(profile).err(), Some(Error::IllegalValue));
        }
    }

    #[test]
    fn the_keys_are_not_printed() {
        let keys = master()
            .srtp_keys(SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32)
            .unwrap();
        assert_eq!(
            format!("{keys:?}"),
            "SrtpKeys { profile: SrtpProtectionProfile(2), .. }"
        );
    }
}
