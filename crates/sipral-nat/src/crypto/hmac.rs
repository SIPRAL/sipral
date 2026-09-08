// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! HMAC (RFC 2104).
//!
//! Keyed by whatever the credential mechanism produced: the password itself
//! for short-term credentials, `MD5(username ":" realm ":" password)` for
//! long-term ones. A key longer than a block is hashed first, a shorter one is
//! padded with zeros, and neither case is reachable from a STUN message, so
//! this takes any key length without complaint.

use super::{BLOCK, Digest};

/// A message authentication code being computed.
pub(crate) struct Hmac<H: Digest> {
    inner: H,
    outer_pad: [u8; BLOCK],
}

impl<H: Digest> Hmac<H> {
    /// Start a code under `key`.
    pub(crate) fn new(key: &[u8]) -> Self {
        let shortened;
        let key = if key.len() > BLOCK {
            shortened = H::digest(key);
            shortened.as_ref()
        } else {
            key
        };

        let mut padded = [0_u8; BLOCK];
        if let Some(room) = padded.get_mut(..key.len()) {
            room.copy_from_slice(key);
        }

        let mut inner_pad = padded;
        let mut outer_pad = padded;
        for (inner, outer) in inner_pad.iter_mut().zip(&mut outer_pad) {
            *inner ^= 0x36;
            *outer ^= 0x5c;
        }

        let mut inner = H::start();
        inner.update(&inner_pad);
        Self { inner, outer_pad }
    }

    /// Add to the text being authenticated.
    pub(crate) fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// The code.
    pub(crate) fn finish(self) -> H::Output {
        let inner = self.inner.finish();
        let mut outer = H::start();
        outer.update(&self.outer_pad);
        outer.update(inner.as_ref());
        outer.finish()
    }
}

#[cfg(test)]
mod tests {
    use super::Hmac;
    use crate::crypto::sha1::Sha1;
    use crate::crypto::sha256::Sha256;
    use crate::crypto::{Digest, hex};

    fn hmac<H: Digest>(key: &[u8], data: &[u8]) -> H::Output {
        let mut mac = Hmac::<H>::new(key);
        mac.update(data);
        mac.finish()
    }

    #[test]
    fn the_published_hmac_sha1_cases_pass() {
        assert_eq!(
            hex(hmac::<Sha1>(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(hmac::<Sha1>(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
    }

    #[test]
    fn the_published_hmac_sha256_cases_pass() {
        assert_eq!(
            hex(hmac::<Sha256>(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(hmac::<Sha256>(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn a_key_longer_than_a_block_is_hashed_first() {
        assert_eq!(
            hex(hmac::<Sha1>(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
        assert_eq!(
            hex(hmac::<Sha256>(
                &[0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn a_key_of_exactly_one_block_is_not_hashed() {
        // the rule is "longer than a block", so 65 bytes is replaced by its
        // digest before use and 64 goes in as it is
        assert_eq!(
            hmac::<Sha1>(&[0xaa; 65], b"boundary"),
            hmac::<Sha1>(&Sha1::digest(&[0xaa; 65]), b"boundary")
        );
        assert_ne!(
            hmac::<Sha1>(&[0xaa; 64], b"boundary"),
            hmac::<Sha1>(&Sha1::digest(&[0xaa; 64]), b"boundary")
        );
    }

    #[test]
    fn feeding_the_text_in_pieces_changes_nothing() {
        let text: Vec<u8> = (0..=255_u8).cycle().take(300).collect();
        let whole = hmac::<Sha256>(b"key", &text);

        for split in [0, 1, 63, 64, 65, 299, 300] {
            let mut mac = Hmac::<Sha256>::new(b"key");
            mac.update(&text[..split]);
            mac.update(&text[split..]);
            assert_eq!(mac.finish(), whole, "split at {split}");
        }
    }
}
