// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A password, and the promise not to leak it.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};
use std::sync::Arc;

/// A password.
///
/// No `Debug`, no `Display`, and no way to read the bytes from outside this
/// module, so it cannot be printed by accident.
///
/// The bytes are overwritten on drop. Best effort only: a guaranteed write
/// needs a volatile write, hence `unsafe`, which this crate denies. An
/// overwrite plus a compiler fence is what safe code can do.
pub struct Secret(Box<[u8]>);

impl Secret {
    /// Take a password.
    #[must_use]
    pub fn new(password: &str) -> Self {
        Self(Box::from(password.as_bytes()))
    }

    /// The parts joined with colons, in a buffer wiped on drop.
    ///
    /// Allocated once at its final length: a growing `Vec` would leave copies
    /// in freed memory. The `join` in `super::digest` is unsuitable because
    /// its capacity is one byte too long, so `into_boxed_slice` would copy.
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

    /// `digest` in lower-case hex (RFC 8760 §2.2), in a buffer wiped on drop
    /// and allocated once.
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
/// Same best effort as [`Secret`]: an overwrite and a fence, since a volatile
/// write needs `unsafe`. Generic over the word sizes the digests use, so one
/// rule covers every buffer.
pub(super) fn wipe<T: Copy + Default>(buffer: &mut [T]) {
    buffer.fill(T::default());
    compiler_fence(Ordering::SeqCst);
}

/// A user name and password for one realm, and, for an OAuth 2.0 server
/// (RFC 8898), the access token that answers a `Bearer` challenge.
///
/// The realm is the caller's book-keeping; one account usually serves both
/// the registrar and its proxy.
///
/// The token is as secret as the password (RFC 6750 §5.3: whoever holds it
/// can use it): no `Debug`, no read-back, wiped on drop.
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

    /// A copy with `token` as the access token (or none), same user name and
    /// password. For renewing a token while the credentials are shared; the
    /// password copy is wiped on drop too.
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
        for good in [
            "abc",
            "eyJhbGciOi.eyJzdWIi.c2ln",
            "a-b_c~d+e/f",
            "QUJD==",
            "x=",
        ] {
            assert!(super::is_access_token(good), "{good}");
        }
        for bad in [
            "",
            "=",
            "==abc",
            "a b",
            "a,b",
            "a\"b",
            "ab=c",
            "a\r\nVia: x",
        ] {
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
