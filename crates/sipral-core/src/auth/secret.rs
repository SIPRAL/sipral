// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

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
        for ([high, low], byte) in bytes.as_chunks_mut::<2>().0.iter_mut().zip(digest) {
            *high = super::digest::nibble(byte >> 4);
            *low = super::digest::nibble(byte & 0x0f);
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

/// A user name and the password that goes with it, for one realm — and, for a
/// server that takes OAuth 2.0 (RFC 8898), the access token that answers a
/// `Bearer` challenge.
///
/// The realm is not part of this: which credentials belong to which realm is
/// the caller's book-keeping, and a device with one account uses the same pair
/// for the registrar and for the proxy in front of it.
///
/// The token is as secret as the password. RFC 6750 §5.3 makes a bearer token
/// something whoever holds it can use, so it gets the same treatment: no
/// `Debug` of it, no way to read it back from outside, and a buffer wiped on
/// drop.
pub struct Credentials {
    /// The user name, which does go in the message and is not a secret.
    pub username: Arc<str>,
    password: Option<Secret>,
    token: Option<Secret>,
}

/// Why a string is not an access token that can go in a `Bearer` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotAToken;

impl fmt::Display for NotAToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "an access token is one or more of A-Z a-z 0-9 - . _ ~ + / \
             followed by any '=' padding (RFC 6750 section 2.1)",
        )
    }
}

impl std::error::Error for NotAToken {}

impl Credentials {
    /// Take a user name and password.
    #[must_use]
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: Arc::from(username),
            password: Some(Secret::new(password)),
            token: None,
        }
    }

    /// An access token alone, for a server that challenges with `Bearer`
    /// and nothing else (RFC 8898). A `Digest` challenge finds no password
    /// here and is not answered.
    ///
    /// # Errors
    /// [`NotAToken`] when `token` is not RFC 6750 §2.1's `b64token`, the
    /// only shape that goes in the field as it is.
    pub fn bearer(token: &str) -> Result<Self, NotAToken> {
        Ok(Self {
            username: Arc::from(""),
            password: None,
            token: Some(token_secret(token)?),
        })
    }

    /// These credentials with `token` as the access token, in place of any
    /// they had; the password, if any, stays.
    ///
    /// # Errors
    /// [`NotAToken`], as [`Self::bearer`].
    pub fn with_access_token(mut self, token: &str) -> Result<Self, NotAToken> {
        self.token = Some(token_secret(token)?);
        Ok(self)
    }

    /// A copy carrying `token` as the access token — or none, for `None` —
    /// with the same user name and password. For a token renewed while the
    /// credentials are shared: the password is copied into a buffer of its
    /// own, wiped on drop like the first.
    ///
    /// # Errors
    /// [`NotAToken`], as [`Self::bearer`].
    pub fn renewed(&self, token: Option<&str>) -> Result<Self, NotAToken> {
        Ok(Self {
            username: Arc::clone(&self.username),
            password: self
                .password
                .as_ref()
                .map(|password| Secret(Box::from(password.expose()))),
            token: token.map(token_secret).transpose()?,
        })
    }

    /// Whether there is a password, which a `Digest` challenge needs.
    #[must_use]
    pub const fn has_password(&self) -> bool {
        self.password.is_some()
    }

    /// Whether there is an access token, which a `Bearer` challenge needs.
    #[must_use]
    pub const fn has_access_token(&self) -> bool {
        self.token.is_some()
    }

    pub(super) fn password(&self) -> Option<&[u8]> {
        self.password.as_ref().map(Secret::expose)
    }

    pub(super) fn token(&self) -> Option<&[u8]> {
        self.token.as_ref().map(Secret::expose)
    }
}

/// Whether `token` is RFC 6750 §2.1's `b64token`: `1*( ALPHA / DIGIT / "-" /
/// "." / "_" / "~" / "+" / "/" ) *"="`, the shape an access token takes in a
/// `Bearer` field.
#[must_use]
pub fn is_access_token(token: &str) -> bool {
    let bytes = token.as_bytes();
    let body = bytes.iter().position(|&b| b == b'=').unwrap_or(bytes.len());
    let (head, padding) = bytes.split_at(body);
    !head.is_empty()
        && head.iter().all(|&b| {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && padding.iter().all(|&b| b == b'=')
}

fn token_secret(token: &str) -> Result<Secret, NotAToken> {
    if is_access_token(token) {
        Ok(Secret::new(token))
    } else {
        Err(NotAToken)
    }
}

impl fmt::Debug for Credentials {
    /// The user name, and no hint of the password or the token beyond
    /// whether there is one.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = |held: bool| if held { "<redacted>" } else { "<none>" };
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &redacted(self.password.is_some()))
            .field("token", &redacted(self.token.is_some()))
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
    fn an_access_token_is_a_b64token() {
        for good in ["abc", "eyJhbGciOi.eyJzdWIi.c2ln", "a-b_c~d+e/f", "QUJD==", "x="] {
            assert!(super::is_access_token(good), "{good}");
        }
        for bad in ["", "=", "==abc", "a b", "a,b", "a\"b", "ab=c", "a\r\nVia: x"] {
            assert!(!super::is_access_token(bad), "{bad:?}");
        }
        assert!(Credentials::bearer("a b").is_err());
    }

    #[test]
    fn a_renewed_token_keeps_the_password_and_hides_both() {
        let first = Credentials::new("alice", "hunter2")
            .with_access_token("first.token")
            .expect("a token");
        let renewed = first.renewed(Some("second.token")).expect("a token");
        assert_eq!(renewed.password(), Some(&b"hunter2"[..]));
        assert_eq!(renewed.token(), Some(&b"second.token"[..]));
        let printed = format!("{renewed:?}");
        assert!(
            !printed.contains("second") && !printed.contains("hunter2"),
            "{printed}"
        );
        let cleared = renewed.renewed(None).expect("no token");
        assert!(!cleared.has_access_token() && cleared.has_password());
        assert!(!Credentials::bearer("t").expect("a token").has_password());
    }

    #[test]
    fn the_password_is_not_in_the_debug_output() {
        let credentials = Credentials::new("alice", "hunter2");
        let printed = format!("{credentials:?}");
        assert!(printed.contains("alice"));
        assert!(!printed.contains("hunter2"), "{printed}");
    }
}
