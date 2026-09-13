// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Stateless HelloVerifyRequest cookies (RFC 6347 §4.2.1).
//!
//! A server that answers the first ClientHello with a cookie, and does no
//! work until the cookie comes back, can be neither made to hold state for
//! forged addresses nor used to flood one. §4.2.1 suggests
//! `Cookie = HMAC(Secret, Client-IP, Client-Parameters)`, which is what this
//! is, with SHA-256.
//!
//! The client address is length-prefixed ahead of the parameters, so that no
//! address and hello can be shifted into another address and hello with the
//! same octets. The parameters are the five fields §4.2.1 makes the client
//! repeat unchanged — version, random, session_id, cipher_suites,
//! compression_methods — and nothing else: extensions may legitimately differ
//! between the two ClientHellos, and the cookie field obviously does.
//!
//! Rotating the secret is the caller's. §4.2.1 suggests changing it often and
//! accepting the previous one for a while; holding two [`CookieSecret`]s and
//! trying both is exactly that.

use core::fmt;

use hmac::Mac;
use zeroize::Zeroizing;

use super::hello::ClientHello;
use crate::prf::{self, HASH_LEN};
use crate::wire;
use crate::{Error, Random, ct};

/// Octets in a cookie made here: a full HMAC-SHA256.
pub const COOKIE_LEN: usize = HASH_LEN;

/// The server's cookie secret.
///
/// Wiped when dropped, and never printed.
pub struct CookieSecret {
    key: Zeroizing<[u8; HASH_LEN]>,
}

impl CookieSecret {
    /// A new secret from the caller's randomness.
    pub fn generate<R: Random + ?Sized>(random: &mut R) -> Self {
        let mut key = Zeroizing::new([0u8; HASH_LEN]);
        random.fill(key.as_mut_slice());
        Self { key }
    }

    /// The cookie for `hello` arriving from `client_address`, in whatever form
    /// the transport names addresses — the same form every time.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] when a field of `hello` is outside the bounds its
    /// wire form allows, which a parsed ClientHello never is.
    pub fn cookie(
        &self,
        client_address: &[u8],
        hello: &ClientHello,
    ) -> Result<[u8; COOKIE_LEN], Error> {
        let mut input = Vec::with_capacity(64 + client_address.len());
        wire::put_vec16(&mut input, client_address, 0, 0xFFFF)?;
        hello.cookie_input(&mut input)?;
        let mut mac = prf::keyed(self.key.as_slice());
        mac.update(&input);
        Ok(mac.finalize().into_bytes().into())
    }

    /// Whether `hello` carries the cookie this secret makes for it and for
    /// `client_address`, compared without stopping at the first difference.
    ///
    /// §4.2.1: a server "SHOULD treat [an invalid cookie] the same as a
    /// ClientHello with no cookie", so there is no error to report — a hello
    /// that does not verify is answered with a fresh HelloVerifyRequest.
    #[must_use]
    pub fn verify(&self, client_address: &[u8], hello: &ClientHello) -> bool {
        self.cookie(client_address, hello)
            .is_ok_and(|expected| ct::equal(&expected, &hello.cookie))
    }
}

impl fmt::Debug for CookieSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CookieSecret").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::extensions::{Extension, Extensions};
    use super::super::hello::{COMPRESSION_NULL, CipherSuite};
    use super::*;
    use crate::prf::tests::hmac;
    use crate::random::testing::Counter;
    use crate::record::ProtocolVersion;

    fn hello() -> ClientHello {
        ClientHello {
            client_version: ProtocolVersion::DTLS_1_2,
            random: [0x42; 32],
            session_id: Vec::new(),
            cookie: Vec::new(),
            cipher_suites: vec![CipherSuite::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
            compression_methods: vec![COMPRESSION_NULL],
            extensions: None,
        }
    }

    const ADDRESS: &[u8] = &[192, 0, 2, 1, 0x13, 0xC4];

    #[test]
    fn the_cookie_is_an_hmac_over_the_address_and_the_five_repeated_fields() {
        let secret = CookieSecret::generate(&mut Counter::new(5));
        let hello = hello();
        let mut input = vec![0, 6];
        input.extend_from_slice(ADDRESS);
        input.extend_from_slice(&[254, 253]);
        input.extend_from_slice(&[0x42; 32]);
        input.push(0);
        input.extend_from_slice(&[0, 2, 0xC0, 0x2B]);
        input.extend_from_slice(&[1, 0]);
        assert_eq!(
            secret.cookie(ADDRESS, &hello),
            Ok(hmac(secret.key.as_slice(), &[&input]))
        );
    }

    #[test]
    fn the_second_client_hello_verifies_whatever_else_changed() {
        let secret = CookieSecret::generate(&mut Counter::new(5));
        let first = hello();
        let mut second = first.clone();
        second.cookie = secret.cookie(ADDRESS, &first).unwrap().to_vec();
        let mut extensions = Extensions::new();
        extensions.push(Extension::ExtendedMasterSecret).unwrap();
        second.extensions = Some(extensions);
        assert!(secret.verify(ADDRESS, &second));
    }

    #[test]
    fn a_cookie_is_refused_for_another_address_hello_or_secret() {
        let secret = CookieSecret::generate(&mut Counter::new(5));
        let mut good = hello();
        good.cookie = secret.cookie(ADDRESS, &good).unwrap().to_vec();
        assert!(secret.verify(ADDRESS, &good));

        assert!(!secret.verify(&[192, 0, 2, 2, 0x13, 0xC4], &good));
        let other_secret = CookieSecret::generate(&mut Counter::new(6));
        assert!(!other_secret.verify(ADDRESS, &good));

        let mut changes: Vec<ClientHello> = Vec::new();
        let mut h = good.clone();
        h.client_version = ProtocolVersion::DTLS_1_0;
        changes.push(h);
        let mut h = good.clone();
        h.random[31] ^= 1;
        changes.push(h);
        let mut h = good.clone();
        h.session_id = vec![1];
        changes.push(h);
        let mut h = good.clone();
        h.cipher_suites
            .push(CipherSuite::EMPTY_RENEGOTIATION_INFO_SCSV);
        changes.push(h);
        let mut h = good.clone();
        h.compression_methods.push(1);
        changes.push(h);
        for (i, changed) in changes.iter().enumerate() {
            assert!(!secret.verify(ADDRESS, changed), "change {i}");
        }

        for position in 0..COOKIE_LEN {
            let mut altered = good.clone();
            altered.cookie[position] ^= 0x80;
            assert!(!secret.verify(ADDRESS, &altered), "octet {position}");
        }
        let mut empty = good.clone();
        empty.cookie.clear();
        assert!(!secret.verify(ADDRESS, &empty));
        let mut longer = good;
        longer.cookie.push(0);
        assert!(!secret.verify(ADDRESS, &longer));
    }

    #[test]
    fn the_address_cannot_trade_octets_with_the_hello() {
        let secret = CookieSecret::generate(&mut Counter::new(5));
        // Two (address, hello) pairs whose fields, laid end to end with no
        // length in front of the address, are the same octets: the second
        // address is one octet shorter, every field of the second hello
        // starts one octet earlier, and its session_id takes the octet back.
        let mut first = hello();
        first.random[31] = 1;
        let mut second = first.clone();
        second.client_version = ProtocolVersion {
            major: ADDRESS[5],
            minor: first.client_version.major,
        };
        second.random[0] = first.client_version.minor;
        second.random[1..].copy_from_slice(&first.random[..31]);
        second.session_id = vec![0];
        let shorter = &ADDRESS[..5];

        let mut joined_first = ADDRESS.to_vec();
        first.cookie_input(&mut joined_first).unwrap();
        let mut joined_second = shorter.to_vec();
        second.cookie_input(&mut joined_second).unwrap();
        assert_eq!(
            joined_first, joined_second,
            "the collision the prefix is there to prevent"
        );

        assert_ne!(
            secret.cookie(ADDRESS, &first),
            secret.cookie(shorter, &second)
        );
    }

    #[test]
    fn the_secret_is_not_printed() {
        let secret = CookieSecret::generate(&mut Counter::new(5));
        assert_eq!(format!("{secret:?}"), "CookieSecret { .. }");
    }
}
