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

    pub(super) fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            *byte = 0;
        }
        compiler_fence(Ordering::SeqCst);
    }
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
    fn the_password_is_not_in_the_debug_output() {
        let credentials = Credentials::new("alice", "hunter2");
        let printed = format!("{credentials:?}");
        assert!(printed.contains("alice"));
        assert!(!printed.contains("hunter2"), "{printed}");
    }
}
