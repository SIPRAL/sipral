// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What it takes to be reachable at an address of record.
//!
//! An account is the configuration of one identity — usually a relationship
//! with one registrar, and sometimes with none, for a trunk that knows this end
//! by the address its requests come from. Several of them coexist in one user
//! agent without sharing anything — not a `Call-ID`, not a sequence number, not
//! a set of credentials. A softphone with a work line and a personal line has
//! two, and neither can affect the other.
//!
//! Two things here are the caller's and not this crate's. The address and the
//! transport, because resolving a server's name is I/O and belongs to
//! whoever owns the sockets; and the instance identifier, because RFC 5626
//! §4.1 requires it to survive a power cycle, and a library with no storage
//! cannot promise that.
//!
//! A third is the push resource identifier. RFC 8599 §4.1.1 puts it in the
//! `Contact` of a REGISTER so that the network can wake a suspended device,
//! and getting one is a conversation with a notification service that has
//! nothing to do with SIP.

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

/// Where a push notification for this account is delivered (RFC 8599 §4.1.1).
///
/// The three values are opaque here and mean something only to the
/// notification service named by `provider`: §8.7 says "the format and
/// semantics of pn-prid and pn-param are specific to the pn-provider value",
/// and §10 to §12 register one triple each for Apple, Firebase and RFC 8030.
/// Obtaining them is the application's — it talks to the service, it owns the
/// entitlements, and a stack that guessed would guess wrong on every platform.
///
/// They go out on REGISTER and nowhere else. §4.1 forbids the parameters in
/// any other request, because a `pn-prid` in the `Contact` of an INVITE hands
/// the far end a token that wakes this device whenever it likes.
#[derive(Clone)]
pub struct Push {
    provider: Box<str>,
    prid: Box<str>,
    param: Option<Box<str>>,
    /// `+sip.pnsreg` (§4.1.4): this device can wake itself to refresh.
    wakes_itself: bool,
}

impl core::fmt::Debug for Push {
    /// The provider, and nothing that identifies the device.
    ///
    /// `pn-prid` is a token that wakes this installation. §4.1 keeps it off
    /// every request but REGISTER for exactly that reason — "a `pn-prid` in
    /// the `Contact` of an INVITE hands the far end a token that wakes this
    /// device whenever it likes" — and a log file is a worse place for it than
    /// an INVITE, because it is kept. `pn-param` goes with it: §8.7 makes both
    /// opaque and service-specific, so neither can be judged safe from here.
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
    /// Notifications of type `provider`, addressed to `prid`.
    ///
    /// `provider` is the registered name of the service — `apns`, `fcm`,
    /// `webpush` — and `prid` the resource identifier it issued for this
    /// installation.
    #[must_use]
    pub fn new(provider: &str, prid: &str) -> Self {
        Self {
            provider: Box::from(provider),
            prid: Box::from(prid),
            param: None,
            wakes_itself: false,
        }
    }

    /// The extra value a service needs beside the identifier: the application
    /// bundle for Apple, the sender for Firebase.
    ///
    /// §4.1.1 makes it mandatory "if required for the specific PNS", so it is
    /// optional here and the service decides.
    #[must_use]
    pub fn param(mut self, param: &str) -> Self {
        self.param = Some(Box::from(param));
        self
    }

    /// This device can send a binding refresh without being woken by a push,
    /// which §4.1.4 makes it say with a `+sip.pnsreg` media feature tag.
    ///
    /// It is the application's fact and not this crate's to guess: a process
    /// the operating system has suspended has no timer that runs, and one that
    /// claims otherwise gets a registrar that stops sending the wake-ups the
    /// device is relying on.
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

    /// `;pn-provider=…;pn-param=…;pn-prid=…`, in the order §4.1.4's example
    /// writes them.
    ///
    /// `removing` leaves out the identifier: §4.1.2 says a REGISTER that gives
    /// up the binding "MUST NOT insert the 'pn-prid' SIP URI parameter", and
    /// its absence is how the network is told to stop sending notifications
    /// for it.
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

/// A URI parameter value, escaped as §25.1's `pvalue` requires.
///
/// A push identifier is whatever the notification service made of it, and two
/// of the three registered services hand out something that is not a SIP token
/// — a base64 identifier carries `=`, a Web Push identifier is a whole URL.
/// §8.7 says as much: "parameter value characters that are not part of pvalue
/// need to be escaped".
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

/// An identity, where its requests go, how to prove it — and, for every
/// account but a trunk, the registrar that keeps it reachable.
#[derive(Clone, Debug)]
pub struct Account {
    /// The address of record: `sip:alice@example.com`. Goes in `To` and
    /// `From` (§10.2).
    pub(crate) aor: Uri,
    /// Where the REGISTER is addressed: `sip:example.com`, no user part.
    ///
    /// `None` for an account that never registers ([`Account::unregistered`]).
    pub(crate) registrar: Option<Uri>,
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
    /// Where this account's requests go when they name nowhere more specific:
    /// the registrar's address for an account that registers, and the
    /// outbound proxy for one that does not.
    pub(crate) remote: SocketAddr,
    pub(crate) extra: Vec<Extra>,
    pub(crate) push: Option<Push>,
}

impl Account {
    /// An account at `aor`, registering with `registrar`, reachable at
    /// `contact`.
    ///
    /// `transport` and `remote` say where the REGISTER actually goes, and
    /// where a call goes when it names no destination of its own. Nothing
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
        Self::with(aor, Some(registrar), contact, transport, remote)
    }

    /// An account at `aor` that never registers, reachable at `contact`,
    /// whose requests go to `outbound_proxy`.
    ///
    /// A trunk, in the usual case: the far end knows this end by the address
    /// its packets come from, so there is no binding to create and none to
    /// keep alive. What exists to protect a binding — the refresh, the
    /// back-off, the recovery ladder after a wake or a move, the refresh a
    /// push asks for, the snapshot — has nothing to do here, and asking this
    /// account to register is refused with
    /// [`UaError::NoRegistrar`](crate::UaError::NoRegistrar) rather than sent
    /// somewhere.
    ///
    /// Everything else is what any account does. A call or a subscription
    /// leaves on `transport` for `outbound_proxy` unless it names a
    /// destination of its own, and a challenge from the proxy is answered
    /// from [`Account::credentials`].
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
            expires: DEFAULT_EXPIRES,
            session_interval: Some(crate::timers::RECOMMENDED),
            instance_id: None,
            transport,
            remote,
            extra: Vec::new(),
            push: None,
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
    ///
    /// Given with or without the angle brackets `+sip.instance` wraps it in:
    /// one pair is taken off here and `Contact` writes the pair back, so an
    /// application that copied the value out of a `Contact` does not send it
    /// bracketed twice.
    #[must_use]
    pub fn instance_id(mut self, urn: &str) -> Self {
        let bare = urn
            .strip_prefix('<')
            .and_then(|inner| inner.strip_suffix('>'))
            .unwrap_or(urn);
        self.instance_id = Some(Box::from(bare));
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

    /// Ask the network to wake this device with push notifications
    /// (RFC 8599 §4.1.1).
    ///
    /// The parameters ride on the `Contact` of every REGISTER and on nothing
    /// else. Whether the network acts on them is
    /// [`UserAgent::push_echo`](crate::UserAgent::push_echo): §4.1.1 says a UA
    /// that gets no `sip.pns` back "MUST NOT assume the proxy will request
    /// that push notifications are sent", and a phone that assumes it goes to
    /// sleep and is never woken again.
    #[must_use]
    pub fn push(mut self, push: Push) -> Self {
        self.push = Some(push);
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

    /// Whether this account asks its registrar for GRUUs (RFC 5627 §4.1).
    ///
    /// Only possible with an instance identifier: GRUUs are handed out per
    /// instance, and a `Contact` naming none cannot carry one. What decides
    /// whether `Supported: gruu` goes on a REGISTER, an INVITE or a SUBSCRIBE,
    /// and whether an incoming `Require: gruu` is honoured rather than
    /// answered 420.
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
    ///
    /// No push parameters, whatever the account was configured with. This is
    /// the `Contact` of a dialog — an INVITE, the 200 that answers one — and
    /// RFC 8599 §4.1 says a UA "MUST NOT insert the SIP URI parameters ... in
    /// non-REGISTER requests in order to prevent the PNS information
    /// associated with the UA from reaching the remote peer". A `pn-prid` that
    /// leaks here is a token that lets whoever it reached wake this device at
    /// will. [`Account::register_contact_value`] is the other one.
    pub(crate) fn contact_value(&self) -> Box<[u8]> {
        self.contact_with(None, false)
    }

    /// `Contact` for a REGISTER, which is the only request the push
    /// parameters belong in.
    ///
    /// `removing` is a REGISTER with `Expires: 0`, where §4.1.2 leaves the
    /// identifier out.
    pub(crate) fn register_contact_value(&self, removing: bool) -> Box<[u8]> {
        self.contact_with(self.push.as_ref(), removing)
    }

    fn contact_with(&self, push: Option<&Push>, removing: bool) -> Box<[u8]> {
        let bytes = self.contact.as_bytes();
        let mut out = Vec::with_capacity(bytes.len() + 128);
        out.push(b'<');
        // URI parameters go before the URI headers (§19.1.1), so a contact
        // written with headers has to be opened up rather than appended to
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
        if let Some(ref urn) = self.instance_id {
            // §4.1: c-p-instance = "+sip.instance" EQUAL
            //         DQUOTE "<" instance-val ">" DQUOTE — the angle brackets
            // are part of the grammar, not decoration, because RFC 3840 §9
            // compares the quoted string case-sensitively and this is the
            // encapsulation that makes that comparison work
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
        // RFC 8599 §12: an RFC 8030 identifier is a whole push endpoint, and
        // §8.7 says what is not a pvalue has to be escaped
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
        // §19.1.1 puts parameters before headers, and appending to a contact
        // that already has headers would produce a URI nobody can parse
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
        // an application that copied the value out of a Contact hands it over
        // bracketed, and RFC 5626 §4.1 writes one pair around it, never two
        let bracketed = account("sip:alice@192.0.2.1").instance_id("<urn:uuid:1234>");
        let bare = account("sip:alice@192.0.2.1").instance_id("urn:uuid:1234");
        assert_eq!(
            rendered(&bracketed, false),
            "<sip:alice@192.0.2.1>;+sip.instance=\"<urn:uuid:1234>\""
        );
        assert_eq!(rendered(&bracketed, false), rendered(&bare, false));
    }
}
