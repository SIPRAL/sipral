// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What it takes to be reachable at an address of record.
//!
//! An account is the configuration of one relationship with one registrar, and
//! several of them coexist in one user agent without sharing anything — not a
//! `Call-ID`, not a sequence number, not a set of credentials. A softphone with
//! a work line and a personal line has two, and neither can affect the other.
//!
//! Two things here are the caller's and not this crate's. The address and the
//! transport, because resolving the registrar's name is I/O and belongs to
//! whoever owns the sockets; and the instance identifier, because RFC 5626
//! §4.1 requires it to survive a power cycle, and a library with no storage
//! cannot promise that.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sipral_core::auth::Credentials;
use sipral_core::endpoint::TransportId;
use sipral_core::msg::{HeaderName, Uri};

/// One hour, which is what most registrars grant anyway.
pub(crate) const DEFAULT_EXPIRES: Duration = Duration::from_hours(1);

/// The name of an account inside one [`UserAgent`](crate::UserAgent).
///
/// Minted by [`UserAgent::add_account`](crate::UserAgent::add_account) and
/// never reused, so a handle to an account that has been removed names nothing
/// rather than naming somebody else's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(pub(crate) u32);

/// One header the caller added to every REGISTER this account sends.
#[derive(Clone, Debug)]
pub(crate) struct Extra {
    pub(crate) name: Box<[u8]>,
    pub(crate) value: Box<[u8]>,
}

/// A registrar, an identity, and how to prove it.
#[derive(Clone, Debug)]
pub struct Account {
    /// The address of record: `sip:alice@example.com`. Goes in `To` and
    /// `From` (§10.2).
    pub(crate) aor: Uri,
    /// Where the REGISTER is addressed: `sip:example.com`, no user part.
    pub(crate) registrar: Uri,
    /// Where this endpoint can be reached, as it goes in `Contact`.
    pub(crate) contact: Uri,
    pub(crate) display_name: Option<Box<str>>,
    /// Refcounted rather than copied: [`Credentials`] is deliberately not
    /// `Clone`, so that the password exists once however many places name it.
    pub(crate) credentials: Option<Arc<Credentials>>,
    pub(crate) expires: Duration,
    /// The session interval to ask for on a call (RFC 4028). `None` asks for
    /// none, and takes one only if the far end insists.
    pub(crate) session_interval: Option<Duration>,
    pub(crate) instance_id: Option<Box<str>>,
    pub(crate) transport: TransportId,
    pub(crate) remote: SocketAddr,
    pub(crate) extra: Vec<Extra>,
}

impl Account {
    /// An account at `aor`, registering with `registrar`, reachable at
    /// `contact`.
    ///
    /// `transport` and `remote` say where the REGISTER actually goes. Nothing
    /// here resolves a name: RFC 3263 is I/O, and the platform's resolver is
    /// better than a protocol library's.
    #[must_use]
    pub fn new(
        aor: Uri,
        registrar: Uri,
        contact: Uri,
        transport: TransportId,
        remote: SocketAddr,
    ) -> Self {
        Self {
            aor,
            registrar,
            contact,
            display_name: None,
            credentials: None,
            expires: DEFAULT_EXPIRES,
            session_interval: Some(crate::timers::RECOMMENDED),
            instance_id: None,
            transport,
            remote,
            extra: Vec::new(),
        }
    }

    /// The display name that goes in `From`.
    #[must_use]
    pub fn display_name(mut self, name: &str) -> Self {
        self.display_name = Some(Box::from(name));
        self
    }

    /// The password to answer a challenge with.
    ///
    /// Left out, a challenge is reported and the registration stops there:
    /// there is nothing to answer with, and sending the request again would
    /// only earn the same refusal.
    #[must_use]
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(Arc::new(credentials));
        self
    }

    /// How long a binding to ask for. One hour unless said otherwise.
    ///
    /// What the registrar grants wins, always (§10.2.4), and the refresh is
    /// scheduled against the granted value rather than this one.
    #[must_use]
    pub const fn expires(mut self, expires: Duration) -> Self {
        self.expires = expires;
        self
    }

    /// The instance identifier, as the `+sip.instance` parameter of `Contact`
    /// (RFC 5626 §4.1).
    ///
    /// A URN, usually `urn:uuid:`, that identifies this device and survives a
    /// power cycle and a change of network. It is the caller's to generate and
    /// to store, because a library that minted one per process would defeat
    /// the point: the value is what lets a registrar replace this device's
    /// binding instead of accumulating one per address it has ever had.
    ///
    /// The `reg-id` parameter that goes with it in an Outbound registration is
    /// deliberately not sent. RFC 5626 §4.2 pairs it with the `outbound` option
    /// tag and with flow keepalive and flow recovery, none of which exists
    /// here yet; claiming the tag without them would be a promise this stack
    /// does not keep.
    #[must_use]
    pub fn instance_id(mut self, urn: &str) -> Self {
        self.instance_id = Some(Box::from(urn));
        self
    }

    /// How long a call may go without a refresh before it is hung up
    /// (RFC 4028 §4).
    ///
    /// Thirty minutes by default, which is the value §4 recommends. `None`
    /// asks for no timer at all — the far end may still impose one, and then
    /// it is honoured, because refusing to refresh a session the other end is
    /// timing is a call that drops for no visible reason.
    #[must_use]
    pub const fn session_interval(mut self, interval: Option<Duration>) -> Self {
        self.session_interval = interval;
        self
    }

    /// A header field on every REGISTER this account sends.
    #[must_use]
    pub fn header(mut self, name: HeaderName<'_>, value: &[u8]) -> Self {
        self.extra.push(Extra {
            name: Box::from(name.canonical().as_bytes()),
            value: Box::from(value),
        });
        self
    }

    /// The address of record, read back.
    #[must_use]
    pub const fn aor(&self) -> &Uri {
        &self.aor
    }

    /// The registrar this account registers with.
    #[must_use]
    pub const fn registrar(&self) -> &Uri {
        &self.registrar
    }

    /// Where this endpoint says it can be reached.
    #[must_use]
    pub const fn contact(&self) -> &Uri {
        &self.contact
    }

    /// `From`, with the display name when there is one. The tag is the
    /// endpoint's to add (§8.1.1.3).
    pub(crate) fn sender_value(&self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(self.aor.as_bytes().len() + 32);
        if let Some(ref name) = self.display_name {
            out.push(b'"');
            for byte in name.as_bytes() {
                // §25.1 quoted-string: a quote or a backslash inside one has
                // to be escaped, or the value ends early
                if matches!(*byte, b'"' | b'\\') {
                    out.push(b'\\');
                }
                out.push(*byte);
            }
            out.extend_from_slice(b"\" ");
        }
        out.push(b'<');
        out.extend_from_slice(self.aor.as_bytes());
        out.push(b'>');
        out.into_boxed_slice()
    }

    /// `To`, which §10.2 makes the address of record being registered.
    pub(crate) fn to_value(&self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(self.aor.as_bytes().len() + 2);
        out.push(b'<');
        out.extend_from_slice(self.aor.as_bytes());
        out.push(b'>');
        out.into_boxed_slice()
    }

    /// `Contact`, with the instance identifier when the account has one.
    pub(crate) fn contact_value(&self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(self.contact.as_bytes().len() + 64);
        out.push(b'<');
        out.extend_from_slice(self.contact.as_bytes());
        out.push(b'>');
        if let Some(ref urn) = self.instance_id {
            // RFC 3840 §9: the value is a quoted string, and RFC 5626 §4.1
            // compares it case-sensitively, so it goes out exactly as given
            out.extend_from_slice(b";+sip.instance=\"");
            out.extend_from_slice(urn.as_bytes());
            out.push(b'"');
        }
        out.into_boxed_slice()
    }
}
