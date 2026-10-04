// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What a dialog is called: a `Call-ID` and two tags (RFC 3261 §12).
//!
//! The two halves are not compared the same way, and the RFC says so in two
//! different places. A `Call-ID` is "case-sensitive and ... simply compared
//! byte-by-byte" (§20.8). A tag is a token, and "Tokens are always
//! case-insensitive" (§7.3.1), so `tag=A1B2` and `tag=a1b2` name one dialog
//! however the peer chose to spell it on the way back.
//!
//! Which tag is ours depends on who started the transaction the message
//! belongs to, not on who started the dialog: our own requests and the
//! responses to them carry our tag in `From`, everything the peer sends
//! carries it in `To`. A lookup therefore needs no memory of which side of
//! the dialog we were.

use core::fmt;
use core::hash::{Hash, Hasher};
use std::sync::Arc;

use super::DialogError;
use crate::msg::RawMessage;

/// A `Call-ID`, compared byte for byte (RFC 3261 §20.8).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CallId(Arc<[u8]>);

impl CallId {
    /// Keep a `Call-ID`.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }

    /// The bytes, as they arrived.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A `tag` parameter, compared without regard to case (§7.3.1).
#[derive(Clone)]
pub struct Tag(Arc<[u8]>);

impl Tag {
    /// Keep a tag.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self(Arc::from(bytes))
    }

    /// The bytes, as they arrived.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for Tag {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }
}

impl Eq for Tag {}

impl Hash for Tag {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // one case, so that two spellings of one tag land in the same bucket
        for b in self.0.iter() {
            state.write_u8(b.to_ascii_lowercase());
        }
        state.write_u8(0xff);
    }
}

/// The name of a dialog: `Call-ID`, our tag, and the peer's if it sent one.
///
/// A peer that predates RFC 3261 may send no tag at all, "in which case the
/// tag is considered to have a value of null" (§12.1.1 and §12.1.2). That is
/// what the `None` is: not a missing field, a dialog with half a name.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DialogKey {
    call_id: CallId,
    local_tag: Tag,
    remote_tag: Option<Tag>,
}

impl DialogKey {
    /// Build a key from its parts.
    #[must_use]
    pub const fn new(call_id: CallId, local_tag: Tag, remote_tag: Option<Tag>) -> Self {
        Self {
            call_id,
            local_tag,
            remote_tag,
        }
    }

    /// The dialog a message of a transaction *we* started names: our request,
    /// or a response to it. Our tag is in `From`.
    ///
    /// # Errors
    /// [`DialogError::MissingTag`] when `From` carries no tag, and
    /// [`DialogError::Field`] when a field is missing or malformed.
    pub fn as_uac(message: &RawMessage<'_>) -> Result<Self, DialogError> {
        let call_id = CallId::new(message.call_id()?);
        let local = message.from()?.tag().ok_or(DialogError::MissingTag)?;
        let remote = message.to()?.tag();
        Ok(Self::new(
            call_id,
            Tag::new(&local),
            remote.map(|t| Tag::new(&t)),
        ))
    }

    /// The dialog a message of a transaction the *peer* started names: their
    /// request, or our response to it. Our tag is in `To`.
    ///
    /// # Errors
    /// [`DialogError::MissingTag`] when `To` carries no tag, and
    /// [`DialogError::Field`] when a field is missing or malformed.
    pub fn as_uas(message: &RawMessage<'_>) -> Result<Self, DialogError> {
        let call_id = CallId::new(message.call_id()?);
        let local = message.to()?.tag().ok_or(DialogError::MissingTag)?;
        let remote = message.from()?.tag();
        Ok(Self::new(
            call_id,
            Tag::new(&local),
            remote.map(|t| Tag::new(&t)),
        ))
    }

    /// The `Call-ID`.
    #[must_use]
    pub const fn call_id(&self) -> &CallId {
        &self.call_id
    }

    /// Our tag.
    #[must_use]
    pub const fn local_tag(&self) -> &Tag {
        &self.local_tag
    }

    /// The peer's tag, when it sent one.
    #[must_use]
    pub const fn remote_tag(&self) -> Option<&Tag> {
        self.remote_tag.as_ref()
    }
}

impl fmt::Debug for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(&self.0))
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(&self.0))
    }
}

impl fmt::Debug for DialogKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} local={:?} remote=", self.call_id, self.local_tag)?;
        match &self.remote_tag {
            Some(tag) => write!(f, "{tag:?}"),
            None => f.write_str("null"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CallId, DialogKey, Tag};
    use crate::msg::{ParseMode, ParseScratch, RawMessage, parse};
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    const INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=AlIcE1\r\n\
To: <sip:bob@example.com>;tag=bob1\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";

    fn with<R>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> R) -> R {
        let mut scratch = ParseScratch::new();
        let message = parse(bytes, &mut scratch, ParseMode::Strict).expect("a message");
        f(&message)
    }

    fn hash_of<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    #[test]
    fn a_call_id_is_compared_byte_for_byte() {
        assert_eq!(CallId::new(b"abc"), CallId::new(b"abc"));
        assert_ne!(CallId::new(b"AbC"), CallId::new(b"abc"));
    }

    #[test]
    fn a_tag_is_a_token_so_its_spelling_does_not_name_a_second_dialog() {
        let (upper, lower) = (Tag::new(b"A1B2"), Tag::new(b"a1b2"));
        assert_eq!(upper, lower);
        assert_eq!(hash_of(&upper), hash_of(&lower), "and lands in one bucket");
        assert_ne!(Tag::new(b"a1b2"), Tag::new(b"a1b3"));
    }

    #[test]
    fn one_tag_is_not_the_prefix_of_the_next() {
        let key = |local: &[u8], remote: &[u8]| {
            DialogKey::new(CallId::new(b"c"), Tag::new(local), Some(Tag::new(remote)))
        };
        assert_ne!(key(b"ab", b"c"), key(b"a", b"bc"));
        assert_ne!(hash_of(&key(b"ab", b"c")), hash_of(&key(b"a", b"bc")));
    }

    #[test]
    fn the_two_roles_read_the_tags_from_opposite_fields() {
        with(INVITE, |message| {
            let ours = DialogKey::as_uac(message).expect("we sent it");
            let theirs = DialogKey::as_uas(message).expect("they sent it");

            assert_eq!(ours.local_tag().as_bytes(), b"AlIcE1");
            assert_eq!(ours.remote_tag().expect("a To tag").as_bytes(), b"bob1");
            assert_eq!(theirs.local_tag().as_bytes(), b"bob1");
            assert_eq!(
                theirs.remote_tag().expect("a From tag").as_bytes(),
                b"AlIcE1"
            );
            assert_eq!(ours.call_id(), theirs.call_id());
            assert_ne!(ours, theirs, "one message, two dialogs, one per end");
        });
    }

    #[test]
    fn a_peer_that_sends_no_tag_leaves_half_a_name() {
        let no_to_tag = b"INVITE sip:bob@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1\r\n\
From: <sip:alice@example.com>;tag=alice1\r\n\
To: <sip:bob@example.com>\r\n\
Call-ID: a84b4c76e66710\r\n\
CSeq: 1 INVITE\r\n\
Content-Length: 0\r\n\
\r\n";
        with(no_to_tag, |message| {
            let key = DialogKey::as_uac(message).expect("our From tag is there");
            assert!(key.remote_tag().is_none(), "null, not missing");
            // and the other way round there is no name at all
            assert!(DialogKey::as_uas(message).is_err());
        });
    }
}
