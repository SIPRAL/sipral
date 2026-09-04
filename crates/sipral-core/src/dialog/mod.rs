// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Dialogs: what two user agents remember about each other (RFC 3261 §12).
//!
//! A transaction lasts one request and its answers. A dialog lasts the call:
//! it is what lets a BYE half an hour later reach the same machine, over the
//! same proxies, with numbers that say which request came first.
//!
//! Four pieces of state carry that, and each exists because of a specific
//! failure without it. The route set is the path the first request took, kept
//! so later ones can take it too — a proxy that record-routed itself is a
//! proxy that has to stay on the path. The remote target is where the peer
//! actually lives, which is rarely the address the call was placed to. The two
//! sequence numbers order the two directions independently. And the tags name
//! the dialog, so that one INVITE which forks to a desk phone and a mobile
//! ends up as two dialogs rather than one confused one.
//!
//! Nothing here decides anything. It records what the messages said and works
//! out what the next message has to look like; which fork to keep and when to
//! hang up belong further up.

mod error;
mod fork;
mod key;
mod request;
mod state;

pub use error::DialogError;
pub use fork::{DialogSet, Fork};
pub use key::{CallId, DialogKey, Tag};
pub use request::InDialogRequest;
pub use state::{Dialog, DialogState, Incoming};
