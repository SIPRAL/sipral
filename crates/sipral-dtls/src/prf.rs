// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The TLS 1.2 pseudorandom function with SHA-256, and the secrets derived
//! through it.
//!
//! RFC 5246 §5 defines one construction, P_SHA256, and every secret a
//! handshake derives comes out of it under a different label: the master
//! secret (§8.1) or the extended master secret (RFC 7627 §4), the
//! `verify_data` of the two Finished messages (§7.4.9), the key block the
//! record layer is keyed from (§6.3), and the exporter (RFC 5705 §4, in
//! [`crate::exporter`]).
//!
//! HMAC and SHA-256 are the RustCrypto implementations. What is written here
//! is only the chaining of §5 and the layout of what comes out.

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::Role;
use crate::record::GcmProtection;

type HmacSha256 = Hmac<Sha256>;

/// Octets in a SHA-256 output, and so in a handshake hash and in one block of
/// P_SHA256.
pub const HASH_LEN: usize = 32;
/// RFC 5246 §8.1: "The master secret is always exactly 48 bytes in length."
pub const MASTER_SECRET_LEN: usize = 48;
/// Octets in `ClientHello.random` and `ServerHello.random`.
pub const RANDOM_LEN: usize = 32;
/// RFC 5246 §7.4.9: the `verify_data_length` of every suite that does not name
/// its own, which includes the one this crate implements.
pub const VERIFY_DATA_LEN: usize = 12;
/// `enc_key_length` of AES-128-GCM.
pub const WRITE_KEY_LEN: usize = 16;
/// `fixed_iv_length` of AES-128-GCM (RFC 5288 §3).
pub const WRITE_IV_LEN: usize = 4;

const MASTER_SECRET: &[u8] = b"master secret";
const EXTENDED_MASTER_SECRET: &[u8] = b"extended master secret";
const KEY_EXPANSION: &[u8] = b"key expansion";
const CLIENT_FINISHED: &[u8] = b"client finished";
const SERVER_FINISHED: &[u8] = b"server finished";

/// Every label the PRF is used with inside the handshake, which an exporter
/// must not be allowed to reuse.
pub(crate) const HANDSHAKE_LABELS: [&[u8]; 5] = [
    MASTER_SECRET,
    EXTENDED_MASTER_SECRET,
    KEY_EXPANSION,
    CLIENT_FINISHED,
    SERVER_FINISHED,
];

/// `PRF(secret, label, seed) = P_SHA256(secret, label + seed)`, as many octets
/// as `out` holds (RFC 5246 §5).
///
/// The seed is given in pieces because every seed the handshake uses is a
/// concatenation — two randoms, or two randoms and a context — and joining
/// them first would only make one more copy of material that is sometimes
/// secret.
pub fn prf(secret: &[u8], label: &[u8], seed: &[&[u8]], out: &mut [u8]) {
    Stream::new(secret, label, seed).fill(out);
}

/// One PRF output laid over several fields in turn, the way RFC 5246 §6.3
/// cuts the key block and RFC 5764 §4.2 cuts the SRTP keying material.
pub(crate) fn prf_fields(secret: &[u8], label: &[u8], seed: &[&[u8]], fields: &mut [&mut [u8]]) {
    let mut stream = Stream::new(secret, label, seed);
    for field in fields {
        stream.fill(field);
    }
}

/// P_SHA256 read out a few octets at a time, so that a layout of several
/// fields can be filled field by field from one expansion.
struct Stream<'a> {
    mac: HmacSha256,
    label: &'a [u8],
    seed: &'a [&'a [u8]],
    /// A(i) of the block being handed out.
    a: [u8; HASH_LEN],
    block: [u8; HASH_LEN],
    /// Octets of `block` already handed out.
    used: usize,
}

impl<'a> Stream<'a> {
    fn new(secret: &[u8], label: &'a [u8], seed: &'a [&'a [u8]]) -> Self {
        let mac = keyed(secret);
        // A(0) = label + seed, so A(1) = HMAC(secret, label + seed)
        let mut first = mac.clone();
        first.update(label);
        for piece in seed {
            first.update(piece);
        }
        Self {
            a: first.finalize().into_bytes().into(),
            mac,
            label,
            seed,
            block: [0; HASH_LEN],
            used: HASH_LEN,
        }
    }

    fn fill(&mut self, out: &mut [u8]) {
        for slot in out {
            if self.used == HASH_LEN {
                self.advance();
            }
            if let Some(byte) = self.block.get(self.used) {
                *slot = *byte;
            }
            self.used += 1;
        }
    }

    /// The next block is HMAC(secret, A(i) + label + seed); A(i+1) is
    /// HMAC(secret, A(i)).
    fn advance(&mut self) {
        let mut output = self.mac.clone();
        output.update(&self.a);
        output.update(self.label);
        for piece in self.seed {
            output.update(piece);
        }
        self.block = output.finalize().into_bytes().into();

        let mut chain = self.mac.clone();
        chain.update(&self.a);
        self.a = chain.finalize().into_bytes().into();
        self.used = 0;
    }
}

impl Drop for Stream<'_> {
    fn drop(&mut self) {
        self.a.zeroize();
        self.block.zeroize();
    }
}

/// HMAC-SHA256 keyed with a secret of any length.
///
/// RFC 2104 §2 replaces a key longer than the 64-octet block with its hash and
/// pads every key with zeros to the block. Doing both here hands the primitive
/// a block-sized key, the one form of keying it offers that cannot fail.
pub(crate) fn keyed(secret: &[u8]) -> HmacSha256 {
    let mut key = hmac::digest::Key::<HmacSha256>::default();
    let mut hashed = [0u8; HASH_LEN];
    let material: &[u8] = if secret.len() > key.len() {
        hashed = Sha256::digest(secret).into();
        &hashed
    } else {
        secret
    };
    for (slot, byte) in key.iter_mut().zip(material) {
        *slot = *byte;
    }
    let mac = <HmacSha256 as KeyInit>::new(&key);
    key.as_mut_slice().zeroize();
    hashed.zeroize();
    mac
}

/// Which of the two computations produced a master secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Derivation {
    /// RFC 7627 §4: from the session hash, which binds the secret to every
    /// handshake message up to ClientKeyExchange.
    Extended,
    /// RFC 5246 §8.1: from the two hello randoms alone.
    Legacy,
}

/// A session's master secret, with the two randoms every later derivation
/// needs beside it (RFC 5246's `SecurityParameters`).
///
/// Wiped when dropped, and never printed.
pub struct MasterSecret {
    secret: Zeroizing<[u8; MASTER_SECRET_LEN]>,
    client_random: [u8; RANDOM_LEN],
    server_random: [u8; RANDOM_LEN],
    derivation: Derivation,
}

impl MasterSecret {
    /// `PRF(pre_master_secret, "extended master secret", session_hash)[0..47]`
    /// (RFC 7627 §4).
    ///
    /// `session_hash` is SHA-256 over every handshake message from ClientHello
    /// up to and including ClientKeyExchange (§3); in DTLS each is hashed as
    /// if sent in one fragment, and the ClientHello answered by a
    /// HelloVerifyRequest is left out with the HelloVerifyRequest itself (RFC
    /// 6347 §4.2.6). [`crate::handshake::Transcript`] produces it.
    ///
    /// `pre_master_secret` is the ECDH x-coordinate with its leading zeros
    /// kept (RFC 8422 §5.10).
    #[must_use]
    pub fn extended(
        pre_master_secret: &[u8],
        session_hash: &[u8; HASH_LEN],
        client_random: [u8; RANDOM_LEN],
        server_random: [u8; RANDOM_LEN],
    ) -> Self {
        let mut secret = Zeroizing::new([0u8; MASTER_SECRET_LEN]);
        prf(
            pre_master_secret,
            EXTENDED_MASTER_SECRET,
            &[session_hash],
            secret.as_mut_slice(),
        );
        Self {
            secret,
            client_random,
            server_random,
            derivation: Derivation::Extended,
        }
    }

    /// `PRF(pre_master_secret, "master secret", ClientHello.random +
    /// ServerHello.random)[0..47]` (RFC 5246 §8.1).
    ///
    /// A session keyed this way can still protect records, but RFC 7627 §5.4
    /// forbids exporting from it, and [`MasterSecret::export`] refuses to.
    #[must_use]
    pub fn legacy(
        pre_master_secret: &[u8],
        client_random: [u8; RANDOM_LEN],
        server_random: [u8; RANDOM_LEN],
    ) -> Self {
        let mut secret = Zeroizing::new([0u8; MASTER_SECRET_LEN]);
        prf(
            pre_master_secret,
            MASTER_SECRET,
            &[&client_random, &server_random],
            secret.as_mut_slice(),
        );
        Self {
            secret,
            client_random,
            server_random,
            derivation: Derivation::Legacy,
        }
    }

    /// How this secret was derived.
    #[must_use]
    pub const fn derivation(&self) -> Derivation {
        self.derivation
    }

    /// `ClientHello.random`.
    #[must_use]
    pub const fn client_random(&self) -> &[u8; RANDOM_LEN] {
        &self.client_random
    }

    /// `ServerHello.random`.
    #[must_use]
    pub const fn server_random(&self) -> &[u8; RANDOM_LEN] {
        &self.server_random
    }

    /// The `verify_data` of the Finished message `sender` sends:
    /// `PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]`
    /// (RFC 5246 §7.4.9).
    ///
    /// Compare a received one with [`crate::handshake::Finished::matches`],
    /// which does not stop at the first differing octet.
    #[must_use]
    pub fn verify_data(
        &self,
        sender: Role,
        handshake_hash: &[u8; HASH_LEN],
    ) -> [u8; VERIFY_DATA_LEN] {
        let label = match sender {
            Role::Client => CLIENT_FINISHED,
            Role::Server => SERVER_FINISHED,
        };
        let mut out = [0u8; VERIFY_DATA_LEN];
        prf(self.secret.as_slice(), label, &[handshake_hash], &mut out);
        out
    }

    /// The key block of RFC 5246 §6.3 for AES-128-GCM:
    /// `PRF(master_secret, "key expansion", server_random + client_random)`,
    /// cut into the two write keys and the two write IVs. The suite has no MAC
    /// keys, so those take no octets.
    #[must_use]
    pub fn key_block(&self) -> KeyBlock {
        let mut block = KeyBlock {
            client_write_key: Zeroizing::new([0; WRITE_KEY_LEN]),
            server_write_key: Zeroizing::new([0; WRITE_KEY_LEN]),
            client_write_iv: Zeroizing::new([0; WRITE_IV_LEN]),
            server_write_iv: Zeroizing::new([0; WRITE_IV_LEN]),
        };
        prf_fields(
            self.secret.as_slice(),
            KEY_EXPANSION,
            &[&self.server_random, &self.client_random],
            &mut [
                block.client_write_key.as_mut_slice(),
                block.server_write_key.as_mut_slice(),
                block.client_write_iv.as_mut_slice(),
                block.server_write_iv.as_mut_slice(),
            ],
        );
        block
    }

    pub(crate) fn secret(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasterSecret")
            .field("derivation", &self.derivation)
            .finish_non_exhaustive()
    }
}

/// The record keys of one session, both directions.
///
/// Wiped when dropped, and never printed.
pub struct KeyBlock {
    client_write_key: Zeroizing<[u8; WRITE_KEY_LEN]>,
    server_write_key: Zeroizing<[u8; WRITE_KEY_LEN]>,
    client_write_iv: Zeroizing<[u8; WRITE_IV_LEN]>,
    server_write_iv: Zeroizing<[u8; WRITE_IV_LEN]>,
}

impl KeyBlock {
    /// The key the records `writer` sends are protected under.
    #[must_use]
    pub fn write_key(&self, writer: Role) -> &[u8; WRITE_KEY_LEN] {
        match writer {
            Role::Client => &self.client_write_key,
            Role::Server => &self.server_write_key,
        }
    }

    /// The implicit part of the nonce of the records `writer` sends.
    #[must_use]
    pub fn write_iv(&self, writer: Role) -> &[u8; WRITE_IV_LEN] {
        match writer {
            Role::Client => &self.client_write_iv,
            Role::Server => &self.server_write_iv,
        }
    }

    /// Record protection for what `writer` sends: the sealing side for
    /// `writer` itself, the opening side for its peer.
    #[must_use]
    pub fn protection(&self, writer: Role) -> GcmProtection {
        GcmProtection::new(self.write_key(writer), self.write_iv(writer))
    }
}

impl fmt::Debug for KeyBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBlock").finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    /// HMAC-SHA256 written out from RFC 2104 over nothing but the hash, so
    /// that the PRF below is checked against a chain that shares no code with
    /// it — not the HMAC crate, not the keying, not the loop.
    pub(crate) fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut block = [0u8; 64];
        if key.len() > 64 {
            block[..32].copy_from_slice(&Sha256::digest(key));
        } else {
            block[..key.len()].copy_from_slice(key);
        }
        let mut inner = Sha256::new();
        inner.update(block.map(|b| b ^ 0x36));
        for part in parts {
            inner.update(part);
        }
        let mut outer = Sha256::new();
        outer.update(block.map(|b| b ^ 0x5c));
        outer.update(inner.finalize());
        outer.finalize().into()
    }

    /// P_SHA256 exactly as RFC 5246 §5 draws it: A(0) = seed,
    /// A(i) = HMAC(secret, A(i-1)), output HMAC(secret, A(i) + seed) for
    /// i = 1, 2, ..., truncated.
    pub(crate) fn p_sha256(secret: &[u8], label_and_seed: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut a = hmac(secret, &[label_and_seed]);
        while out.len() < len {
            out.extend_from_slice(&hmac(secret, &[&a, label_and_seed]));
            a = hmac(secret, &[&a]);
        }
        out.truncate(len);
        out
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn the_reference_hmac_matches_rfc_4231() {
        // test case 1
        assert_eq!(
            hmac(&[0x0b; 20], &[b"Hi There"]).to_vec(),
            hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        // test case 2
        assert_eq!(
            hmac(b"Jefe", &[b"what do ya want ", b"for nothing?"]).to_vec(),
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        // test case 6, a key longer than the block
        assert_eq!(
            hmac(
                &[0xaa; 131],
                &[b"Test Using Larger Than Block-Size Key - Hash Key First"]
            )
            .to_vec(),
            hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn the_prf_is_p_sha256_over_label_and_seed_at_every_length() {
        let secrets: [&[u8]; 4] = [b"", &[0x42; 20], &[0x17; 64], &[0x99; 100]];
        let label = b"slithy toves";
        let seed_a = [1u8; 32];
        let seed_b = [2u8; 7];
        for secret in secrets {
            for len in [0, 1, 12, 31, 32, 33, 48, 64, 80, 100] {
                let mut ours = vec![0u8; len];
                prf(secret, label, &[&seed_a, &seed_b], &mut ours);
                let mut joined = label.to_vec();
                joined.extend_from_slice(&seed_a);
                joined.extend_from_slice(&seed_b);
                assert_eq!(
                    ours,
                    p_sha256(secret, &joined, len),
                    "secret of {} octets, {len} octets out",
                    secret.len()
                );
            }
        }
    }

    #[test]
    fn the_master_secrets_follow_their_two_formulas() {
        let pre_master = [0x0au8; 32];
        let client_random = [0xc1u8; 32];
        let server_random = [0x5eu8; 32];
        let session_hash = [0x33u8; 32];

        let legacy = MasterSecret::legacy(&pre_master, client_random, server_random);
        let mut seed = b"master secret".to_vec();
        seed.extend_from_slice(&client_random);
        seed.extend_from_slice(&server_random);
        assert_eq!(legacy.secret(), p_sha256(&pre_master, &seed, 48));
        assert_eq!(legacy.derivation(), Derivation::Legacy);

        let extended =
            MasterSecret::extended(&pre_master, &session_hash, client_random, server_random);
        let mut seed = b"extended master secret".to_vec();
        seed.extend_from_slice(&session_hash);
        assert_eq!(extended.secret(), p_sha256(&pre_master, &seed, 48));
        assert_eq!(extended.derivation(), Derivation::Extended);
        assert_eq!(extended.client_random(), &client_random);
        assert_eq!(extended.server_random(), &server_random);
    }

    #[test]
    fn each_side_finishes_under_its_own_label() {
        let master = MasterSecret::extended(&[1; 32], &[2; 32], [3; 32], [4; 32]);
        let hash = [0x77u8; 32];
        for (role, label) in [
            (Role::Client, "client finished"),
            (Role::Server, "server finished"),
        ] {
            let mut seed = label.as_bytes().to_vec();
            seed.extend_from_slice(&hash);
            assert_eq!(
                master.verify_data(role, &hash).to_vec(),
                p_sha256(master.secret(), &seed, 12)
            );
        }
    }

    #[test]
    fn the_key_block_is_cut_in_the_order_of_rfc_5246() {
        let master = MasterSecret::extended(&[5; 32], &[6; 32], [0xc1; 32], [0x5e; 32]);
        // server_random first, then client_random
        let mut seed = b"key expansion".to_vec();
        seed.extend_from_slice(&[0x5e; 32]);
        seed.extend_from_slice(&[0xc1; 32]);
        let expected = p_sha256(master.secret(), &seed, 40);

        let block = master.key_block();
        assert_eq!(block.write_key(Role::Client)[..], expected[0..16]);
        assert_eq!(block.write_key(Role::Server)[..], expected[16..32]);
        assert_eq!(block.write_iv(Role::Client)[..], expected[32..36]);
        assert_eq!(block.write_iv(Role::Server)[..], expected[36..40]);
    }

    #[test]
    fn nothing_secret_is_printed() {
        let master = MasterSecret::extended(&[1; 32], &[2; 32], [3; 32], [4; 32]);
        let printed = format!("{master:?} {:?}", master.key_block());
        assert_eq!(
            printed,
            "MasterSecret { derivation: Extended, .. } KeyBlock { .. }"
        );
    }
}
