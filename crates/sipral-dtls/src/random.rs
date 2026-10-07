// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Where the randomness comes from: the caller.

/// A source of cryptographically secure random octets, supplied by the caller.
///
/// Caller-supplied so tests are deterministic and the application chooses
/// the source.
///
/// Every secret here (ECDH and ECDSA keys, hello randoms, cookie secret) is
/// only as unpredictable as this. A seeded generator is acceptable only if
/// the seed came from OS entropy.
pub trait Random {
    /// Fill every octet of `dest`.
    fn fill(&mut self, dest: &mut [u8]);
}

#[cfg(test)]
pub(crate) mod testing {
    use super::Random;
    use sha2::{Digest, Sha256};

    /// SHA-256 in counter mode over a fixed seed: reproducible, and useless
    /// for anything but a test.
    pub(crate) struct Counter {
        seed: u64,
        counter: u64,
    }

    impl Counter {
        pub(crate) const fn new(seed: u64) -> Self {
            Self { seed, counter: 0 }
        }
    }

    impl Random for Counter {
        fn fill(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(32) {
                let block = Sha256::new()
                    .chain_update(self.seed.to_be_bytes())
                    .chain_update(self.counter.to_be_bytes())
                    .finalize();
                self.counter += 1;
                for (slot, byte) in chunk.iter_mut().zip(block.iter()) {
                    *slot = *byte;
                }
            }
        }
    }

    /// A source that returns the same octet forever.
    pub(crate) struct Stuck(pub(crate) u8);

    impl Random for Stuck {
        fn fill(&mut self, dest: &mut [u8]) {
            dest.fill(self.0);
        }
    }
}
