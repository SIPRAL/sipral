// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Accounts: one identity each, usually with a registrar, sometimes none (a
//! trunk). Accounts in one agent share nothing: no `Call-ID`, no sequence
//! number, no credentials.
//!
//! The caller supplies the server address (resolving is I/O), the instance
//! identifier (RFC 5626 §4.1 needs it to survive a power cycle) and the push
//! identifier (RFC 8599, obtained from the notification service).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use sipral_core::auth::Credentials;
use sipral_core::endpoint::{TransportId, TransportProtocol};
use sipral_core::msg::{HeaderName, Uri};
use sipral_core::pin::CertificatePin;

use crate::identity::{ANONYMOUS_FROM, Privacy};

pub(crate) const DEFAULT_EXPIRES: Duration = Duration::from_hours(1);

/// The name of an account inside one [`UserAgent`](crate::UserAgent).
///
/// Minted by [`UserAgent::add_account`](crate::UserAgent::add_account) and
/// never reused, so a stale handle names nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(pub(crate) u32);

#[derive(Clone, Debug)]
pub(crate) struct Extra {
    pub(crate) name: Box<[u8]>,
    pub(crate) value: Box<[u8]>,
}

/// Where a push notification for this account is delivered (RFC 8599 §4.1.1).
///
/// The values are opaque, meaningful only to the service (§8.7); the
/// application obtains them. They go out on REGISTER only (§4.1): a `pn-prid`
/// in an INVITE would let the far end wake this device at will.
#[derive(Clone)]
pub struct Push {
    provider: Box<str>,
    prid: Box<str>,
    param: Option<Box<str>>,
    /// `+sip.pnsreg` (§4.1.4): this device can wake itself to refresh.
    wakes_itself: bool,
}

impl core::fmt::Debug for Push {
    /// Redacts `pn-prid` and `pn-param`: the identifier wakes the device, and
    /// a log keeps it longer than an INVITE would.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Push")
            .field("provider", &self.provider)
            .field("prid", &"<redacted>")
            .field("param", &self.param.as_ref().map(|_| "<redacted>"))
            .field("wakes_itself", &self.wakes_itself)
            .finish()
    }
}

impl Push {
    /// Notifications from `provider` (`apns`, `fcm`, `webpush`) to the
    /// identifier `prid` it issued.
    #[must_use]
    pub fn new(provider: &str, prid: &str) -> Self {
        Self {
            provider: Box::from(provider),
            prid: Box::from(prid),
            param: None,
            wakes_itself: false,
        }
    }

    /// `pn-param`: the app bundle for Apple, the sender for Firebase. Needed
    /// only when the service requires it (§4.1.1).
    #[must_use]
    pub fn param(mut self, param: &str) -> Self {
        self.param = Some(Box::from(param));
        self
    }

    /// This device can refresh its binding without a push (`+sip.pnsreg`,
    /// §4.1.4). Claim it only if true: the registrar may stop the wake-ups.
    #[must_use]
    pub const fn wakes_itself(mut self) -> Self {
        self.wakes_itself = true;
        self
    }

    /// The service this asks for, as it goes on the wire.
    #[must_use]
    pub const fn provider(&self) -> &str {
        &self.provider
    }

    /// `;pn-provider=…;pn-param=…;pn-prid=…`. `removing` omits `pn-prid`
    /// (§4.1.2).
    fn write(&self, out: &mut Vec<u8>, removing: bool) {
        out.extend_from_slice(b";pn-provider=");
        escape(out, &self.provider);
        if let Some(ref param) = self.param {
            out.extend_from_slice(b";pn-param=");
            escape(out, param);
        }
        if !removing {
            out.extend_from_slice(b";pn-prid=");
            escape(out, &self.prid);
        }
    }
}

/// Escape a URI parameter value as `pvalue` (RFC 3261 §25.1). Push
/// identifiers carry `=` or whole URLs (RFC 8599 §8.7).
fn escape(out: &mut Vec<u8>, value: &str) {
    for byte in value.as_bytes() {
        // param-unreserved / unreserved, §25.1
        if byte.is_ascii_alphanumeric()
            || matches!(
                *byte,
                b'-' | b'_'
                    | b'.'
                    | b'!'
                    | b'~'
                    | b'*'
                    | b'\''
                    | b'('
                    | b')'
                    | b'['
                    | b']'
                    | b'/'
                    | b':'
                    | b'&'
                    | b'+'
                    | b'$'
            )
        {
            out.push(*byte);
            continue;
        }
        out.push(b'%');
        out.push(hex(byte >> 4));
        out.push(hex(byte & 0x0f));
    }
}

const fn hex(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        _ => b'A' + nibble - 10,
    }
}

/// The transport of an [`Account::on_stream`] account before its connection
/// exists; nothing is bound under it.
pub(crate) const NO_FLOW_YET: TransportId = TransportId(u32::MAX);

/// An identity, where its requests go, how to prove it, and (except for a
/// trunk) the registrar that keeps it reachable.
#[derive(Clone, Debug)]
pub struct Account {
    pub(crate) aor: Uri,
    /// `None` for an account that never registers.
    pub(crate) registrar: Option<Uri>,
    pub(crate) contact: Uri,
    pub(crate) display_name: Option<Box<str>>,
    /// Shared, not copied: [`Credentials`] is deliberately not `Clone`.
    pub(crate) credentials: Option<Arc<Credentials>>,
    pub(crate) realms: Vec<Arc<str>>,
    /// With no realms configured, those the server first challenged with,
    /// plus whatever the registrar challenges REGISTERs with.
    pub(crate) pinned_realms: Vec<Arc<str>>,
    pub(crate) expires: Duration,
    pub(crate) session_interval: Option<Duration>,
    pub(crate) instance_id: Option<Box<str>>,
    pub(crate) transport: TransportId,
    /// The registrar, or the outbound proxy for an account that does not
    /// register.
    pub(crate) remote: SocketAddr,
    pub(crate) extra: Vec<Extra>,
    pub(crate) push: Option<Push>,
    pub(crate) message_types: Vec<Box<[u8]>>,
    pub(crate) protocol: Option<TransportProtocol>,
    pub(crate) quality_report_uri: Option<Uri>,
    pub(crate) privacy: Privacy,
    pub(crate) trusted: Vec<IpAddr>,
    pub(crate) stir_verification: crate::StirVerification,
    #[cfg(feature = "stir")]
    pub(crate) stir_signing: Option<crate::StirSigning>,
    pub(crate) keepalive: Option<Duration>,
    /// The URI `remote` is found from by RFC 3263, for a located account.
    pub(crate) server: Option<Uri>,
    pub(crate) naptr: bool,
    /// `remote` is a real address: always, or after the first lookup.
    pub(crate) located: bool,
    pub(crate) tls_pin: Option<CertificatePin>,
    pub(crate) own_stream: Option<TransportProtocol>,
}

impl Account {
    /// An account at `aor`, registering with `registrar`, reachable at
    /// `contact`.
    ///
    /// `transport` and `remote` are where the REGISTER goes, and any request
    /// that names no destination of its own. No name is resolved here.
    #[must_use]
    pub fn new(
        aor: Uri,
        registrar: Uri,
        contact: Uri,
        transport: TransportId,
        remote: SocketAddr,
    ) -> Self {
        Self::with(aor, Some(registrar), contact, transport, remote)
    }

    /// An account at `aor` that never registers, reachable at `contact`,
    /// whose requests go to `outbound_proxy`.
    ///
    /// Usually a trunk that knows this end by source address. Asking it to
    /// register fails with
    /// [`UaError::NoRegistrar`](crate::UaError::NoRegistrar). Requests go to
    /// `outbound_proxy` unless they name a destination, and its challenges
    /// are answered from [`Account::credentials`].
    #[must_use]
    pub fn unregistered(
        aor: Uri,
        contact: Uri,
        transport: TransportId,
        outbound_proxy: SocketAddr,
    ) -> Self {
        Self::with(aor, None, contact, transport, outbound_proxy)
    }

    fn with(
        aor: Uri,
        registrar: Option<Uri>,
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
            realms: Vec::new(),
            pinned_realms: Vec::new(),
            expires: DEFAULT_EXPIRES,
            session_interval: Some(crate::timers::RECOMMENDED),
            instance_id: None,
            transport,
            remote,
            extra: Vec::new(),
            push: None,
            message_types: Vec::new(),
            protocol: None,
            quality_report_uri: None,
            privacy: Privacy::default(),
            trusted: Vec::new(),
            stir_verification: crate::StirVerification::default(),
            #[cfg(feature = "stir")]
            stir_signing: None,
            keepalive: None,
            server: None,
            naptr: false,
            located: true,
            tls_pin: None,
            own_stream: None,
        }
    }

    /// Like [`Account::new`], but the registrar's address is found from its
    /// host by RFC 3263.
    ///
    /// Each lookup is asked of the application
    /// ([`UaEvent::LookupWanted`](crate::UaEvent::LookupWanted), answered by
    /// [`UserAgent::looked_up`](crate::UserAgent::looked_up)); ordering, SRV
    /// ranking and fallback are [`sipral_core::endpoint::Locator`]'s. The SRV
    /// name follows `transport`. A port skips SRV; a numeric host asks
    /// nothing.
    ///
    /// The first REGISTER waits for the first answer. An out-of-dialog
    /// request that times out, fails at transport or gets 503 moves to the
    /// next address (§4.3); when none is left or the TTL expires, the name is
    /// looked up again (see [`crate::locate`]). Before the first answer, a
    /// request with no destination of its own fails with
    /// [`UaError::NotLocated`](crate::UaError::NotLocated).
    #[must_use]
    pub fn located(aor: Uri, registrar: Uri, contact: Uri, transport: TransportId) -> Self {
        let mut account = Self::with(
            aor,
            Some(registrar.clone()),
            contact,
            transport,
            SocketAddr::from(([0, 0, 0, 0], 0)),
        );
        account.server = Some(registrar);
        account.located = false;
        account
    }

    /// [`Account::unregistered`], with the outbound proxy located as in
    /// [`Account::located`]. The first lookup starts on the next round of
    /// work after the account is added.
    #[must_use]
    pub fn unregistered_located(
        aor: Uri,
        contact: Uri,
        transport: TransportId,
        outbound_proxy: Uri,
    ) -> Self {
        let mut account = Self::with(
            aor,
            None,
            contact,
            transport,
            SocketAddr::from(([0, 0, 0, 0], 0)),
        );
        account.server = Some(outbound_proxy);
        account.located = false;
        account
    }

    /// Send requests to `server`, located by RFC 3263, instead of the address
    /// given (e.g. an outbound proxy known by name). The REGISTER's
    /// Request-URI is unchanged.
    #[must_use]
    pub fn locate(mut self, server: Uri) -> Self {
        self.server = Some(server);
        self.located = false;
        self.remote = SocketAddr::from(([0, 0, 0, 0], 0));
        self
    }

    /// Look up NAPTR before SRV (RFC 3263 §4.1) for a located account. Off by
    /// default, since most domains publish none.
    #[must_use]
    pub const fn naptr(mut self) -> Self {
        self.naptr = true;
        self
    }

    /// The URI located by RFC 3263, or `None`.
    #[must_use]
    pub const fn server(&self) -> Option<&Uri> {
        self.server.as_ref()
    }

    /// `None` while a located account has no answer yet.
    pub(crate) const fn destination(&self) -> Option<(TransportId, SocketAddr)> {
        if self.located {
            Some((self.transport, self.remote))
        } else {
            None
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
    /// Without it a challenge is reported and the registration stops.
    ///
    /// Only the account's own server is answered (RFC 3261 §22.1): a
    /// challenge from elsewhere, or for a realm not the account's
    /// ([`Account::realms`]), is reported as
    /// [`UaEvent::ChallengeDeclined`](crate::UaEvent::ChallengeDeclined).
    #[must_use]
    pub fn credentials(mut self, credentials: Credentials) -> Self {
        self.credentials = Some(Arc::new(credentials));
        self
    }

    /// The realms the password answers. When set, only these, REGISTERs
    /// included.
    ///
    /// Unset (the default), the account keeps the realms its server first
    /// challenged with, so a proxy relaying a far end's 401 gets nothing.
    /// Realms a registrar uses on REGISTER are always added, so a realm
    /// change is followed. An SBC that challenges calls under a realm
    /// REGISTERs never see needs both realms named here.
    #[must_use]
    pub fn realms(mut self, realms: &[&str]) -> Self {
        self.realms = realms.iter().map(|realm| Arc::from(*realm)).collect();
        self
    }

    /// How long a binding to ask for (default one hour). The refresh follows
    /// what the registrar grants (§10.2.4).
    #[must_use]
    pub const fn expires(mut self, expires: Duration) -> Self {
        self.expires = expires;
        self
    }

    /// The `+sip.instance` URN (RFC 5626 §4.1), usually `urn:uuid:`. The
    /// caller stores it across restarts so the registrar replaces this
    /// device's binding. Angle brackets are optional.
    ///
    /// `reg-id` is not sent: RFC 5626 §4.2 ties it to the `outbound` tag and
    /// flow recovery, which this stack does not claim.
    #[must_use]
    pub fn instance_id(mut self, urn: &str) -> Self {
        let bare = urn
            .strip_prefix('<')
            .and_then(|inner| inner.strip_suffix('>'))
            .unwrap_or(urn);
        self.instance_id = Some(Box::from(bare));
        self
    }

    /// The session timer to ask for (RFC 4028 §4), thirty minutes by default. `None` asks for no timer, but one the far
    /// end imposes is still honoured, or the call would drop.
    #[must_use]
    pub const fn session_interval(mut self, interval: Option<Duration>) -> Self {
        self.session_interval = interval;
        self
    }

    /// Ask the network to wake this device with push notifications
    /// (RFC 8599 §4.1.1).
    ///
    /// Sent on REGISTER only. Whether the network accepted them is
    /// [`UserAgent::push_echo`](crate::UserAgent::push_echo); without that
    /// echo, do not rely on push (§4.1.1).
    #[must_use]
    pub fn push(mut self, push: Push) -> Self {
        self.push = Some(push);
        self
    }

    /// Where to send an end-of-call voice quality report (RFC 6035),
    /// carried by a PUBLISH (RFC 3903). Unset, none is sent.
    #[must_use]
    pub fn quality_report_uri(mut self, uri: Uri) -> Self {
        self.quality_report_uri = Some(uri);
        self
    }

    /// Where this account's voice quality reports go, if it sends any.
    #[must_use]
    pub const fn quality_report(&self) -> Option<&Uri> {
        self.quality_report_uri.as_ref()
    }

    /// Place every call anonymously (RFC 3323); [`Privacy::withheld`] is the
    /// usual choice.
    ///
    /// `From` becomes the anonymous URI (§4.1.1.3), `Privacy` is added, and a
    /// temporary GRUU is used if the account has one (RFC 5627 §3.3). The
    /// real identity goes in `P-Asserted-Identity` only toward a trusted peer
    /// ([`Account::trust`], RFC 3325 §7). A call that sets its own `Privacy`
    /// keeps it. Off by default.
    #[must_use]
    pub const fn privacy(mut self, privacy: Privacy) -> Self {
        self.privacy = privacy;
        self
    }

    /// Put the peer at `address` in the trust domain (RFC 3325 §2.3).
    ///
    /// Only calls from a trusted peer have `P-Asserted-Identity`,
    /// `Remote-Party-ID` and `verstat` read into
    /// [`CallerIdentity`](crate::CallerIdentity) (§8). Calls toward an
    /// untrusted peer carry no `P-Asserted-Identity` or
    /// `P-Preferred-Identity`, whoever set them (§6).
    ///
    /// Once per peer; nobody is trusted by default.
    #[must_use]
    pub fn trust(mut self, address: IpAddr) -> Self {
        if !self.trusted.contains(&address) {
            self.trusted.push(address);
        }
        self
    }

    /// How incoming `Identity` headers are verified (RFC 8224 §6.2); see
    /// [`StirVerification`](crate::StirVerification).
    #[must_use]
    pub const fn stir_verification(mut self, verification: crate::StirVerification) -> Self {
        self.stir_verification = verification;
        self
    }

    /// Sign every call placed (RFC 8224 §6.1, RFC 8588 SHAKEN) with an
    /// `Identity` header and its `Date`. Without
    /// [`UserAgent::set_wall_clock`] a call fails with
    /// [`UaError::NoWallClock`](crate::UaError::NoWallClock), never unsigned.
    ///
    /// [`UserAgent::set_wall_clock`]: crate::UserAgent::set_wall_clock
    #[cfg(feature = "stir")]
    #[must_use]
    pub fn stir_signing(mut self, signing: crate::StirSigning) -> Self {
        self.stir_signing = Some(signing);
        self
    }

    /// Keep the flow to the registrar (or outbound proxy) open with a CRLF
    /// keep-alive every `every`, whether or not STUN found a NAT.
    ///
    /// On UDP a lone double CRLF, which the registrar ignores (RFC 3261 §7.5)
    /// but the NAT sees (RFC 4787 REQ-6); on a stream, RFC 5626 §4.4.1 pings.
    /// Intervals are drawn from 80-100% of `every` (§4.4). Never sent while
    /// suspended. Unset, only a NAT found by STUN gets keep-alives
    /// ([`crate::keepalive`]).
    ///
    /// # Errors
    /// [`UaError::InvalidKeepalive`](crate::UaError::InvalidKeepalive) for an
    /// interval under [`MIN_KEEPALIVE`](crate::keepalive::MIN_KEEPALIVE) or
    /// over [`MAX_KEEPALIVE`](crate::keepalive::MAX_KEEPALIVE).
    pub fn keepalive(mut self, every: Duration) -> Result<Self, crate::UaError> {
        if !(crate::keepalive::MIN_KEEPALIVE..=crate::keepalive::MAX_KEEPALIVE).contains(&every) {
            return Err(crate::UaError::InvalidKeepalive(every));
        }
        self.keepalive = Some(every);
        Ok(self)
    }

    /// The keep-alive interval [`Account::keepalive`] set, or `None`.
    #[must_use]
    pub const fn keepalive_interval(&self) -> Option<Duration> {
        self.keepalive
    }

    /// Trust the TLS server by the SHA-256 fingerprint of its certificate
    /// instead of a trust anchor, e.g. a self-signed PBX.
    ///
    /// TLS is the application's (`docs/22-tls.md`): its verifier reads
    /// [`Account::pinned_certificate`] and calls [`CertificatePin::check`] on
    /// the leaf's DER bytes. With a pin, the fingerprint is the whole verdict:
    /// no chain or host name is checked, and a matching expired certificate
    /// is accepted and reported as expired (see `sipral_core::pin`).
    #[must_use]
    pub const fn tls_pin(mut self, pin: CertificatePin) -> Self {
        self.tls_pin = Some(pin);
        self
    }

    /// The pin [`Account::tls_pin`] set, if any.
    #[must_use]
    pub const fn pinned_certificate(&self) -> Option<&CertificatePin> {
        self.tls_pin.as_ref()
    }

    /// Whether a peer at `address` is one this account trusts.
    #[must_use]
    pub fn trusts(&self, address: IpAddr) -> bool {
        self.trusted.contains(&address)
    }

    /// `From` for a call, anonymous when privacy is asked (RFC 3323 §4.1.1.3).
    pub(crate) fn caller_value(&self) -> Box<[u8]> {
        if self.privacy.requested() {
            Box::from(ANONYMOUS_FROM)
        } else {
            self.sender_value()
        }
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

    /// Accept MESSAGE bodies of `media_type`, besides `text/plain` (always
    /// accepted, RFC 3428 §7). Other types get a 415 with `Accept`; see
    /// [`crate::UaEvent::MessageReceived`]. Call once per type.
    #[must_use]
    pub fn accepts_message_type(mut self, media_type: &[u8]) -> Self {
        self.message_types.push(Box::from(media_type));
        self
    }

    /// Declare the transport's protocol. Unset, out-of-dialog MESSAGEs stay
    /// under 1300 bytes (RFC 3428 §8); a reliable protocol lifts that, for
    /// the first hop only.
    #[must_use]
    pub const fn transport_protocol(mut self, protocol: TransportProtocol) -> Self {
        self.protocol = Some(protocol);
        self
    }

    /// Use a TCP, TLS or WebSocket connection of its own to its server, which
    /// the application opens when asked by
    /// [`Event::TransportWanted`](sipral_core::endpoint::Event::TransportWanted)
    /// (for WebSocket, the TCP/TLS connection bound as `Ws`/`Wss`; the
    /// handshake is [`crate::websocket`]'s). The first transport of
    /// `protocol` bound to the server's address is adopted; until then a
    /// REGISTER waits and a call fails for an unknown transport. Each account
    /// keeps its own flow, and its calls keep it. Implies
    /// [`Account::transport_protocol`]; a datagram protocol changes nothing
    /// else.
    #[must_use]
    pub const fn on_stream(mut self, protocol: TransportProtocol) -> Self {
        if protocol.is_reliable() {
            self.own_stream = Some(protocol);
            self.transport = NO_FLOW_YET;
        }
        self.protocol = Some(protocol);
        self
    }

    /// The address of record, read back.
    #[must_use]
    pub const fn aor(&self) -> &Uri {
        &self.aor
    }

    /// The registrar this account registers with, or `None` for one that
    /// never registers.
    #[must_use]
    pub const fn registrar(&self) -> Option<&Uri> {
        self.registrar.as_ref()
    }

    /// Where this endpoint says it can be reached.
    #[must_use]
    pub const fn contact(&self) -> &Uri {
        &self.contact
    }

    /// Whether this account asks for GRUUs (RFC 5627 §4.1), which needs an
    /// instance identifier. Decides `Supported: gruu` and `Require: gruu`.
    pub(crate) const fn wants_gruu(&self) -> bool {
        self.instance_id.is_some()
    }

    /// `From`, with the display name when there is one. The tag is the
    /// endpoint's to add (§8.1.1.3).
    pub(crate) fn sender_value(&self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(self.aor.as_bytes().len() + 32);
        if let Some(ref name) = self.display_name {
            out.push(b'"');
            for byte in name.as_bytes() {
                // §25.1 quoted-string
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

    /// `To`: the address of record (§10.2).
    pub(crate) fn to_value(&self) -> Box<[u8]> {
        let mut out = Vec::with_capacity(self.aor.as_bytes().len() + 2);
        out.push(b'<');
        out.extend_from_slice(self.aor.as_bytes());
        out.push(b'>');
        out.into_boxed_slice()
    }

    /// `Contact`, with the instance identifier when the account has one.
    ///
    /// Never with push parameters (RFC 8599 §4.1); see
    /// [`Account::register_contact_value`].
    pub(crate) fn contact_value(&self) -> Box<[u8]> {
        self.contact_with(None, false)
    }

    /// `Contact` for a REGISTER, with push parameters. `removing` is
    /// `Expires: 0`, which omits `pn-prid` (§4.1.2).
    pub(crate) fn register_contact_value(&self, removing: bool) -> Box<[u8]> {
        self.contact_with(self.push.as_ref(), removing)
    }

    /// `Contact` removing only this address's binding: the bare URI, without
    /// feature tags. A registrar matching by `+sip.instance` would otherwise
    /// remove every binding of the instance, including one added in the same
    /// REGISTER.
    pub(crate) fn removal_contact_value(&self) -> Box<[u8]> {
        self.bracketed_uri(self.push.as_ref(), true)
            .into_boxed_slice()
    }

    fn contact_with(&self, push: Option<&Push>, removing: bool) -> Box<[u8]> {
        let mut out = self.bracketed_uri(push, removing);
        if let Some(ref urn) = self.instance_id {
            // RFC 5626 §4.1: the brackets are part of the grammar
            out.extend_from_slice(b";+sip.instance=\"<");
            out.extend_from_slice(urn.as_bytes());
            out.extend_from_slice(b">\"");
        }
        if push.is_some_and(|push| push.wakes_itself) {
            // §8.5: the media feature tag has no values
            out.extend_from_slice(b";+sip.pnsreg");
        }
        out.into_boxed_slice()
    }

    fn bracketed_uri(&self, push: Option<&Push>, removing: bool) -> Vec<u8> {
        let bytes = self.contact.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() + 128);
        out.push(b'<');
        // URI parameters go before URI headers (§19.1.1)
        let cut = bytes
            .iter()
            .position(|byte| *byte == b'?')
            .unwrap_or(bytes.len());
        out.extend_from_slice(bytes.get(..cut).unwrap_or(bytes));
        if let Some(push) = push {
            push.write(&mut out, removing);
        }
        out.extend_from_slice(bytes.get(cut..).unwrap_or_default());
        out.push(b'>');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{Account, Push};
    use std::net::SocketAddr;

    use sipral_core::endpoint::TransportId;
    use sipral_core::msg::Uri;

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).expect("a URI")
    }

    fn account(contact: &str) -> Account {
        Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri(contact),
            TransportId(1),
            "192.0.2.9:5060".parse::<SocketAddr>().expect("an address"),
        )
    }

    fn rendered(account: &Account, removing: bool) -> String {
        String::from_utf8_lossy(&account.register_contact_value(removing)).into_owned()
    }

    #[test]
    fn a_push_identifier_that_is_a_url_survives_being_a_uri_parameter() {
        // RFC 8599 §8.7, §12
        let account = account("sip:alice@192.0.2.1")
            .push(Push::new("webpush", "https://push.example.net/sub/A1?k=v#f").param("aBcD=="));
        assert_eq!(
            rendered(&account, false),
            "<sip:alice@192.0.2.1;pn-provider=webpush;pn-param=aBcD%3D%3D;\
             pn-prid=https://push.example.net/sub/A1%3Fk%3Dv%23f>"
        );
    }

    #[test]
    fn the_push_parameters_go_in_front_of_the_uri_headers_and_not_after_them() {
        // RFC 3261 §19.1.1
        let account = account("sip:alice@192.0.2.1?Subject=call").push(Push::new("apns", "p1"));
        assert_eq!(
            rendered(&account, false),
            "<sip:alice@192.0.2.1;pn-provider=apns;pn-prid=p1?Subject=call>"
        );
    }

    #[test]
    fn an_account_without_push_writes_the_contact_it_always_wrote() {
        let account = account("sip:alice@192.0.2.1").instance_id("urn:uuid:1234");
        assert_eq!(rendered(&account, false), rendered(&account, true));
        assert_eq!(
            rendered(&account, false),
            "<sip:alice@192.0.2.1>;+sip.instance=\"<urn:uuid:1234>\""
        );
    }

    #[test]
    fn an_instance_given_with_its_brackets_is_not_bracketed_twice() {
        let bracketed = account("sip:alice@192.0.2.1").instance_id("<urn:uuid:1234>");
        let bare = account("sip:alice@192.0.2.1").instance_id("urn:uuid:1234");
        assert_eq!(
            rendered(&bracketed, false),
            "<sip:alice@192.0.2.1>;+sip.instance=\"<urn:uuid:1234>\""
        );
        assert_eq!(rendered(&bracketed, false), rendered(&bare, false));
    }
}
