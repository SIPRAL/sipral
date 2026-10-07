// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Dialogs: what two user agents remember about each other (RFC 3261 §12).
//!
//! A dialog holds the route set (proxies that record-routed stay on the
//! path), the remote target, one sequence number per direction, and the
//! tags, so that a forked INVITE becomes several dialogs rather than one.
//! It only records and builds; which fork to keep belongs further up.

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
