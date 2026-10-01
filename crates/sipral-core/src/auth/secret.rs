// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! A password, and the promise not to leak it.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};
use std::sync::Arc;

/// A password.
///
/// There is no `Debug`, no `Display` and no way to get the bytes out from
/// outside this module — a value that cannot be printed cannot be printed by
/// accident, which is the only kind of leak that actually happens.
///
/// The bytes are overwritten when the value is dropped. That is best effort
/// and said so plainly: only a volatile write is guaranteed to survive an
/// optimiser, and a volatile write needs `unsafe`, which this crate denies. A
/// compiler fence after the overwrite is what is available without it, and it
/// is what every other safe implementation does.
pub struct Secret(Box<[u8]>);

impl Secret {
    /// Take a password.
    #[must_use]
    pub fn new(password: &str) -> Self {
        Self(Box::from(password.as_bytes()))
    }

    /// The parts joined with colons, in a buffer that is wiped on drop.
    ///
    /// One exact allocation, on purpose. A `Vec` grown part by part
    /// reallocates as it goes and leaves every intermediate copy in freed
    /// memory, which is the thing this type exists to prevent, so the length
    /// is worked out first and the buffer is never grown. The `join` in
    /// `super::digest` cannot be used for it: its capacity is deliberately
    /// one byte longer than the result, so `into_boxed_slice` on what it
    /// returns would reallocate and leave a copy behind.
    pub(super) fn joined(parts: &[&[u8]]) -> Self {
        let total =
            parts.iter().map(|part| part.len()).sum::<usize>() + parts.len().saturating_sub(1);
        let mut bytes = vec![0_u8; total].into_boxed_slice();
        let mut at = 0_usize;
        for (index, part) in parts.iter().enumerate() {
            if index > 0 {
                if let Some(colon) = bytes.get_mut(at) {
                    *colon = b':';
                }
                at = at.saturating_add(1);
            }
            let end = at.saturating_add(part.len());
            if let Some(slot) = bytes.get_mut(at..end) {
                slot.copy_from_slice(part);
            }
            at = end;
        }
        Self(bytes)
    }

    /// `digest` in lower-case hexadecimal (RFC 8760 §2.2), in a buffer that
    /// is wiped on drop and allocated once at its final length.
    pub(super) fn hex(digest: &[u8]) -> Self {
        let mut bytes = vec![0_u8; digest.len().saturating_mul(2)].into_boxed_slice();
        for (pair, byte) in bytes.chunks_exact_mut(2).zip(digest) {
            if let [high, low] = pair {
                *high = super::digest::nibble(byte >> 4);
                *low = super::digest::nibble(byte & 0x0f);
            }
        }
        Self(bytes)
    }

    pub(super) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Overwrite a buffer that held secret material.
///
/// The same best effort [`Secret`] makes for itself, and said as plainly:
/// only a volatile write is guaranteed to survive an optimiser, a volatile
/// write needs `unsafe`, and this crate denies it. What is available without
/// it is an ordinary overwrite and a fence the compiler may not reorder
/// across, which is what every other safe implementation does.
///
/// It takes any word the digests work in — bytes, and the 32- and 64-bit
/// words a message schedule is the message read back as — so that one rule
/// covers every buffer rather than each of them repeating it differently.
pub(super) fn wipe<T: Copy + Default>(buffer: &mut [T]) {
    buffer.fill(T::default());
    compiler_fence(Ordering::SeqCst);
}

/// A user name and the password that goes with it, for one realm.
///
/// The realm is not part of this: which credentials belong to which realm is
/// the caller's book-keeping, and a device with one account uses the same pair
/// for the registrar and for the proxy in front of it.
pub struct Credentials {
    /// The user name, which does go in the message and is not a secret.
    pub username: Arc<str>,
    password: Secret,
}

impl Credentials {
    /// Take a user name and password.
    #[must_use]
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: Arc::from(username),
            password: Secret::new(password),
        }
    }

    pub(super) fn password(&self) -> &[u8] {
        self.password.expose()
    }
}

impl fmt::Debug for Credentials {
    /// The user name, and no hint of the password beyond its absence.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{Credentials, Secret};

    #[test]
    fn a_secret_is_the_bytes_it_was_given() {
        let secret = Secret::new("Circle Of Life");
        assert_eq!(secret.expose(), b"Circle Of Life");
    }

    #[test]
    fn a_joined_secret_is_the_colon_separated_parts() {
        // the A1 of RFC 3261 §22.4, in a buffer that wipes itself rather than
        // in one grown a part at a time
        assert_eq!(
            Secret::joined(&[b"alice", b"example.com", b"hunter2"]).expose(),
            b"alice:example.com:hunter2"
        );
        assert_eq!(Secret::joined(&[b"alone"]).expose(), b"alone");
        assert_eq!(Secret::joined(&[]).expose(), b"");
        assert_eq!(Secret::joined(&[b"", b""]).expose(), b":");
    }

    #[test]
    fn the_password_is_not_in_the_debug_output() {
        let credentials = Credentials::new("alice", "hunter2");
        let printed = format!("{credentials:?}");
        assert!(printed.contains("alice"));
        assert!(!printed.contains("hunter2"), "{printed}");
    }
}
