// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The conference event package: `application/conference-info+xml`, and the
//! picture of a conference a subscriber keeps from it (RFC 4575).
//!
//! A focus reports a conference in documents that are either the whole of it
//! or only what changed (§4.6), numbered by a `version` that goes up by one
//! with every notification of one subscription. [`ConferenceInfo`] is one such
//! document; [`Conference`] is what the documents add up to, merged by the
//! rules of §4.6.
//!
//! **The reader is the one [`crate::DialogInfo`] is read with, and inherits
//! every refusal.**
//! These bodies arrive from whatever answered a SUBSCRIBE, exactly like dialog
//! information, so there is no document type declaration, no entity other
//! than the five predefined ones and character references, no CDATA, and the
//! size, the nesting and the element count are bounded before anything is
//! kept. Namespaces are read as prefixes and otherwise ignored, for the same
//! reason as there: the `Content-Type` says what the body is, and the local
//! name says what an element is.
//!
//! **A partial document is only ever applied on top of the one before it.**
//! §4.6 has a partial notification carry the changes since the previous
//! version, so applying one whose predecessor was lost merges a delta onto
//! the wrong base, and the picture drifts from the focus's with nothing to
//! say so. A gap is therefore not merged: [`Conference::apply`] answers
//! [`ConferenceUpdate::Resubscribe`], and the refresh
//! ([`UserAgent::request_full_state`]) gets full state back: a notifier
//! answers every accepted or refreshed SUBSCRIBE with the current state
//! (RFC 6665 §4.2.1), which for this package is full state. Until it
//! arrives, further partial documents are held off rather than asked about
//! again, so a focus that keeps notifying while the refresh is in flight does
//! not turn into one SUBSCRIBE per NOTIFY.
//!
//! **What is held is bounded like what is read.** Every document is bounded,
//! but partial ones only add up: a merge that would hold more than one
//! full-state document can carry, or more rows in a list than one may list,
//! is not kept, and is answered like a gap.
//!
//! **What is keyed is merged; what is not is replaced.** Under §4.6 a partial
//! element's children are matched to what is held by their key — a user and
//! an endpoint by `entity`, a media stream by `id`, an available-media entry
//! by `label`, a URI entry by its `uri` — and merged in turn; a child that is
//! not keyed replaces the held value when it is present and leaves it alone
//! when it is not. An element marked `deleted` is removed, and one marked
//! `full` replaces what was held for it whole.

use std::time::Instant;

use sipral_core::msg::{OwnedMessage, Uri};

use crate::agent::UserAgent;
use crate::dialoginfo::{Attributes, DialogInfoError, Node, Reader, as_str, local_name, unescape};
use crate::error::UaError;
use crate::subscription::{Subscribe, SubscriptionHandle};

/// The event package's name (RFC 4575 §3.1).
pub const CONFERENCE_EVENT: &str = "conference";
/// The body type its notifications carry (RFC 4575 §3.5).
pub const CONFERENCE_INFO_TYPE: &str = "application/conference-info+xml";

/// The largest document that will be read at all. A conference of a few
/// hundred participants, each with an endpoint and two streams, stays well
/// under it.
const MAX_BYTES: usize = 256 * 1024;
/// How deep the elements may nest. The deepest path in §5 is
/// `conference-info` → `users` → `user` → `endpoint` → `joining-info` →
/// `when`: six.
const MAX_DEPTH: usize = 10;
/// How many nodes will be read before the document is refused.
const MAX_NODES: usize = 65_536;
/// The longest text one element may hold.
const MAX_TEXT: usize = 4_096;
/// How many users one conference may hold.
const MAX_USERS: usize = 1_024;
/// How many endpoints one user may hold.
const MAX_ENDPOINTS: usize = 16;
/// How many media streams one endpoint may hold.
const MAX_MEDIA: usize = 16;
/// How many entries one list of URIs, roles or available media may hold.
const MAX_ENTRIES: usize = 32;

/// Why a conference information document could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConferenceInfoError {
    /// The body is not XML, the markup does not close, or a mandatory part of
    /// the document is missing.
    Malformed(&'static str),
    /// A construct the reader refuses on sight (see [`crate::DialogInfoError`]).
    Refused(&'static str),
    /// One of the bounds in this module was reached.
    TooLarge(&'static str),
    /// A value that has to be text is not UTF-8.
    NotUtf8,
    /// The body is not an `application/conference-info+xml` document.
    NotConferenceInfo,
}

impl core::fmt::Display for ConferenceInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Malformed(what) => write!(f, "malformed conference information: {what}"),
            Self::Refused(what) => write!(f, "refused: {what}"),
            Self::TooLarge(what) => write!(f, "too large: {what}"),
            Self::NotUtf8 => f.write_str("not UTF-8"),
            Self::NotConferenceInfo => f.write_str("not a conference-info document"),
        }
    }
}

impl core::error::Error for ConferenceInfoError {}

impl From<DialogInfoError> for ConferenceInfoError {
    fn from(error: DialogInfoError) -> Self {
        match error {
            DialogInfoError::Malformed(what) => Self::Malformed(what),
            DialogInfoError::Refused(what) => Self::Refused(what),
            DialogInfoError::TooLarge(what) => Self::TooLarge(what),
            DialogInfoError::NotUtf8 => Self::NotUtf8,
            DialogInfoError::NotDialogInfo => Self::NotConferenceInfo,
        }
    }
}

// -- a document as a tree ----------------------------------------------------

/// One element of a document read by [`read_tree`]: its local name, its
/// attributes, its text and its children, in order.
pub(crate) struct XmlNode<'a> {
    /// The name with any namespace prefix taken off.
    pub(crate) name: &'a [u8],
    /// The attributes, read on demand.
    pub(crate) attributes: Attributes<'a>,
    /// The character data directly inside it, references resolved.
    pub(crate) text: Vec<u8>,
    /// The elements directly inside it.
    pub(crate) children: Vec<XmlNode<'a>>,
}

impl<'a> XmlNode<'a> {
    /// The first child called `name`.
    pub(crate) fn child(&self, name: &str) -> Option<&XmlNode<'a>> {
        self.children
            .iter()
            .find(|child| child.name == name.as_bytes())
    }

    /// Every child called `name`, in document order.
    pub(crate) fn children_named<'s>(
        &'s self,
        name: &'s str,
    ) -> impl Iterator<Item = &'s XmlNode<'a>> + 's {
        self.children
            .iter()
            .filter(move |child| child.name == name.as_bytes())
    }

    /// The text, with the whitespace around it taken off.
    pub(crate) fn trimmed(&self) -> Result<&str, DialogInfoError> {
        as_str(self.text.trim_ascii())
    }

    /// The trimmed text of the first child called `name`, when there is one.
    pub(crate) fn child_text(&self, name: &str) -> Result<Option<Box<str>>, DialogInfoError> {
        self.child(name)
            .map(|child| child.trimmed().map(Box::from))
            .transpose()
    }
}

/// The bounds one [`read_tree`] holds a document to.
#[derive(Clone, Copy)]
pub(crate) struct TreeLimits {
    /// The largest body read at all.
    pub(crate) bytes: usize,
    /// How deep elements may nest.
    pub(crate) depth: usize,
    /// How many nodes are read before the document is refused.
    pub(crate) nodes: usize,
    /// The longest text one element may hold.
    pub(crate) text: usize,
}

/// Read a whole document into a tree, over [`crate::dialoginfo`]'s tokeniser.
///
/// Everything that tokeniser refuses is refused here, and the bounds are
/// checked as the document is read rather than after: nothing past the
/// nesting, the node count or the text length is ever kept.
pub(crate) fn read_tree(body: &[u8], limits: TreeLimits) -> Result<XmlNode<'_>, DialogInfoError> {
    if body.len() > limits.bytes {
        return Err(DialogInfoError::TooLarge("document"));
    }
    let mut reader = Reader::new(body);
    let mut open: Vec<XmlNode<'_>> = Vec::new();
    let mut root: Option<XmlNode<'_>> = None;
    for _ in 0..limits.nodes {
        let Some(node) = reader.next()? else {
            if !open.is_empty() {
                return Err(DialogInfoError::Malformed("an element never closed"));
            }
            return root.ok_or(DialogInfoError::Malformed("no root element"));
        };
        match node {
            Node::Open(element) => {
                if root.is_some() {
                    return Err(DialogInfoError::Malformed("markup after the root element"));
                }
                if open.len() >= limits.depth {
                    return Err(DialogInfoError::TooLarge("nesting"));
                }
                let fresh = XmlNode {
                    name: local_name(element.name),
                    attributes: element.attributes,
                    text: Vec::new(),
                    children: Vec::new(),
                };
                if element.empty {
                    attach(&mut open, &mut root, fresh);
                } else {
                    open.push(fresh);
                }
            }
            Node::Close(name) => {
                let closed = open
                    .pop()
                    .filter(|closed| closed.name == local_name(name))
                    .ok_or(DialogInfoError::Malformed("closing tag does not match"))?;
                attach(&mut open, &mut root, closed);
            }
            Node::Text(raw) => {
                let Some(current) = open.last_mut() else {
                    return Err(DialogInfoError::Malformed("text outside the root element"));
                };
                let text = unescape(raw)?;
                if current.text.len().saturating_add(text.len()) > limits.text {
                    return Err(DialogInfoError::TooLarge("element content"));
                }
                current.text.extend_from_slice(&text);
            }
        }
    }
    Err(DialogInfoError::TooLarge("element count"))
}

fn attach<'a>(open: &mut [XmlNode<'a>], root: &mut Option<XmlNode<'a>>, node: XmlNode<'a>) {
    match open.last_mut() {
        Some(parent) => parent.children.push(node),
        None => *root = Some(node),
    }
}

// -- the document ------------------------------------------------------------

/// What one element of a document says about the element it describes
/// (the `state` attribute of RFC 4575 §5).
///
/// In a [`Conference`] every element is settled, and reads
/// [`ElementState::Full`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum ElementState {
    /// This is all of it: it replaces what was held (the schema's default).
    #[default]
    Full,
    /// Only what changed: it is merged into what was held.
    Partial,
    /// It is gone.
    Deleted,
}

impl ElementState {
    fn read(attributes: Attributes<'_>) -> Result<Self, DialogInfoError> {
        match attributes.value("state")? {
            None => Ok(Self::Full),
            Some(value) if value.eq_ignore_ascii_case(b"full") => Ok(Self::Full),
            Some(value) if value.eq_ignore_ascii_case(b"partial") => Ok(Self::Partial),
            Some(value) if value.eq_ignore_ascii_case(b"deleted") => Ok(Self::Deleted),
            Some(_) => Err(DialogInfoError::Malformed(
                "state is not full, partial or deleted",
            )),
        }
    }
}

/// One `entry` of `conf-uris`, `service-uris` or `host-info`'s `uris`
/// (§5): a way into the conference, or a service around it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UriEntry {
    /// The URI, which is what the entry is keyed by.
    pub uri: Box<str>,
    /// Its `display-text`.
    pub display_text: Option<Box<str>>,
    /// Its `purpose`: `participation`, `streaming`, `web-page` and so on.
    pub purpose: Option<Box<str>>,
}

/// Whether a stream is flowing, and which way (§5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MediaStatus {
    /// Only towards the participant.
    RecvOnly,
    /// Only from the participant.
    SendOnly,
    /// Both ways.
    SendRecv,
    /// Neither.
    Inactive,
    /// A value the schema does not list, kept as written.
    Other(Box<str>),
}

impl MediaStatus {
    fn read(text: &str) -> Self {
        for (name, value) in [
            ("recvonly", Self::RecvOnly),
            ("sendonly", Self::SendOnly),
            ("sendrecv", Self::SendRecv),
            ("inactive", Self::Inactive),
        ] {
            if text.eq_ignore_ascii_case(name) {
                return value;
            }
        }
        Self::Other(Box::from(text))
    }
}

/// One `entry` of `available-media` (§5): a stream the conference
/// offers, keyed by its `label`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AvailableMedia {
    /// The `label` attribute, which ties it to the SDP of the focus.
    pub label: Box<str>,
    /// Its `display-text`.
    pub display_text: Option<Box<str>>,
    /// Its `type`: `audio`, `video`, `text`, `message`.
    pub media_type: Option<Box<str>>,
    /// Its `status`.
    pub status: Option<MediaStatus>,
}

/// The `conference-description` element (§5): what the conference is.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConferenceDescription {
    /// How the document described it.
    pub state: ElementState,
    /// `display-text`.
    pub display_text: Option<Box<str>>,
    /// `subject`.
    pub subject: Option<Box<str>>,
    /// `free-text`.
    pub free_text: Option<Box<str>>,
    /// `keywords`.
    pub keywords: Option<Box<str>>,
    /// `conf-uris`: how to join.
    pub conf_uris: Vec<UriEntry>,
    /// `service-uris`: what else there is.
    pub service_uris: Vec<UriEntry>,
    /// `maximum-user-count`.
    pub maximum_user_count: Option<u32>,
    /// `available-media`.
    pub available_media: Vec<AvailableMedia>,
}

/// The `host-info` element (§5): who runs the conference.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostInfo {
    /// How the document described it.
    pub state: ElementState,
    /// `display-text`.
    pub display_text: Option<Box<str>>,
    /// `web-page`.
    pub web_page: Option<Box<str>>,
    /// `uris`.
    pub uris: Vec<UriEntry>,
}

/// The `conference-state` element (§5): how the conference is doing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConferenceStatus {
    /// How the document described it.
    pub state: ElementState,
    /// `user-count`: how many users are in it.
    pub user_count: Option<u32>,
    /// `active`: whether it is running.
    pub active: Option<bool>,
    /// `locked`: whether it has stopped letting anyone in.
    pub locked: Option<bool>,
}

/// Where an endpoint is in the conference (§5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EndpointStatus {
    /// Waiting for policy or for the focus.
    Pending,
    /// The focus is calling it.
    DialingOut,
    /// It is calling the focus.
    DialingIn,
    /// It is ringing.
    Alerting,
    /// It is held.
    OnHold,
    /// It is in.
    Connected,
    /// The focus has muted it.
    MutedViaFocus,
    /// It is being taken out.
    Disconnecting,
    /// It is out.
    Disconnected,
    /// A value the schema does not list, kept as written.
    Other(Box<str>),
}

impl EndpointStatus {
    fn read(text: &str) -> Self {
        for (name, value) in [
            ("pending", Self::Pending),
            ("dialing-out", Self::DialingOut),
            ("dialing-in", Self::DialingIn),
            ("alerting", Self::Alerting),
            ("on-hold", Self::OnHold),
            ("connected", Self::Connected),
            ("muted-via-focus", Self::MutedViaFocus),
            ("disconnecting", Self::Disconnecting),
            ("disconnected", Self::Disconnected),
        ] {
            if text.eq_ignore_ascii_case(name) {
                return value;
            }
        }
        Self::Other(Box::from(text))
    }
}

/// How an endpoint came to be in the conference (§5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum JoiningMethod {
    /// It called in.
    DialedIn,
    /// The focus called it.
    DialedOut,
    /// It is the focus's owner, and was there from the start.
    FocusOwner,
    /// A value the schema does not list, kept as written.
    Other(Box<str>),
}

impl JoiningMethod {
    fn read(text: &str) -> Self {
        for (name, value) in [
            ("dialed-in", Self::DialedIn),
            ("dialed-out", Self::DialedOut),
            ("focus-owner", Self::FocusOwner),
        ] {
            if text.eq_ignore_ascii_case(name) {
                return value;
            }
        }
        Self::Other(Box::from(text))
    }
}

/// How an endpoint came to leave the conference (§5).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DisconnectionMethod {
    /// It hung up.
    Departed,
    /// It was thrown out.
    Booted,
    /// The focus could not reach it, or lost it.
    Failed,
    /// It was busy when the focus called.
    Busy,
    /// A value the schema does not list, kept as written.
    Other(Box<str>),
}

impl DisconnectionMethod {
    fn read(text: &str) -> Self {
        for (name, value) in [
            ("departed", Self::Departed),
            ("booted", Self::Booted),
            ("failed", Self::Failed),
            ("busy", Self::Busy),
        ] {
            if text.eq_ignore_ascii_case(name) {
                return value;
            }
        }
        Self::Other(Box::from(text))
    }
}

/// `joining-info` or `disconnection-info` (§5): when, why and
/// by whom.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExecutionInfo {
    /// `when`, as written: an `xs:dateTime`.
    pub when: Option<Box<str>>,
    /// `reason`.
    pub reason: Option<Box<str>>,
    /// `by`: who did it.
    pub by: Option<Box<str>>,
}

/// One `media` element (§5): a stream an endpoint has with the focus,
/// keyed by its `id`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Media {
    /// The `id` attribute.
    pub id: Box<str>,
    /// `display-text`.
    pub display_text: Option<Box<str>>,
    /// `type`: `audio`, `video` and so on.
    pub media_type: Option<Box<str>>,
    /// `label`, which ties it to an `available-media` entry.
    pub label: Option<Box<str>>,
    /// `src-id`: the SSRC it is sent with, for RTP.
    pub src_id: Option<Box<str>>,
    /// `status`.
    pub status: Option<MediaStatus>,
}

/// One `endpoint` element (§5): one device of a user, keyed by its
/// `entity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint {
    /// How the document described it.
    pub state: ElementState,
    /// The `entity` attribute.
    pub entity: Box<str>,
    /// `display-text`.
    pub display_text: Option<Box<str>>,
    /// `status`.
    pub status: Option<EndpointStatus>,
    /// `joining-method`.
    pub joining_method: Option<JoiningMethod>,
    /// `joining-info`.
    pub joining_info: Option<ExecutionInfo>,
    /// `disconnection-method`.
    pub disconnection_method: Option<DisconnectionMethod>,
    /// `disconnection-info`.
    pub disconnection_info: Option<ExecutionInfo>,
    /// Its streams.
    pub media: Vec<Media>,
}

/// One `user` element (§5): a participant, keyed by its `entity`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct User {
    /// How the document described it.
    pub state: ElementState,
    /// The `entity` attribute.
    pub entity: Box<str>,
    /// `display-text`.
    pub display_text: Option<Box<str>>,
    /// `roles`: every `entry` inside it.
    pub roles: Vec<Box<str>>,
    /// Its devices.
    pub endpoints: Vec<Endpoint>,
}

/// The `users` element (§5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Users {
    /// How the document described it.
    pub state: ElementState,
    /// The users it lists.
    pub users: Vec<User>,
}

/// One `application/conference-info+xml` document (§5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConferenceInfo {
    /// The `entity` attribute: the conference's URI.
    pub entity: Box<str>,
    /// The `version` attribute, which orders the documents of one
    /// subscription (§4.6).
    pub version: u32,
    /// Whether it is the whole conference or what changed. Never
    /// [`ElementState::Deleted`]: a conference that is over ends its
    /// subscription instead.
    pub state: ElementState,
    /// `conference-description`.
    pub description: Option<ConferenceDescription>,
    /// `host-info`.
    pub host: Option<HostInfo>,
    /// `conference-state`.
    pub status: Option<ConferenceStatus>,
    /// `users`.
    pub users: Option<Users>,
}

impl ConferenceInfo {
    /// Read one document.
    ///
    /// # Errors
    /// [`ConferenceInfoError`]. A failure changes nothing a [`Conference`]
    /// already holds.
    pub fn parse(body: &[u8]) -> Result<Self, ConferenceInfoError> {
        let root = read_tree(
            body,
            TreeLimits {
                bytes: MAX_BYTES,
                depth: MAX_DEPTH,
                nodes: MAX_NODES,
                text: MAX_TEXT,
            },
        )?;
        if root.name != b"conference-info" {
            return Err(ConferenceInfoError::NotConferenceInfo);
        }
        // §5: both attributes are mandatory, and §4.6 cannot order a
        // document without its version
        let entity = root
            .attributes
            .text("entity")?
            .ok_or(ConferenceInfoError::Malformed("no entity"))?;
        let version = root
            .attributes
            .text("version")?
            .and_then(|text| text.parse::<u32>().ok())
            .ok_or(ConferenceInfoError::Malformed("no version"))?;
        let state = ElementState::read(root.attributes)?;
        if state == ElementState::Deleted {
            return Err(ConferenceInfoError::Malformed(
                "a document is full or partial",
            ));
        }
        Ok(Self {
            entity,
            version,
            state,
            description: root
                .child("conference-description")
                .map(read_description)
                .transpose()?,
            host: root.child("host-info").map(read_host).transpose()?,
            status: root
                .child("conference-state")
                .map(read_status)
                .transpose()?,
            users: root.child("users").map(read_users).transpose()?,
        })
    }
}

fn bounded<T>(
    items: impl Iterator<Item = Result<T, DialogInfoError>>,
    cap: usize,
    what: &'static str,
) -> Result<Vec<T>, DialogInfoError> {
    let mut out = Vec::new();
    for item in items {
        if out.len() >= cap {
            return Err(DialogInfoError::TooLarge(what));
        }
        out.push(item?);
    }
    Ok(out)
}

fn number(node: &XmlNode<'_>, name: &str) -> Result<Option<u32>, DialogInfoError> {
    Ok(node
        .child_text(name)?
        .and_then(|text| text.parse::<u32>().ok()))
}

/// `xs:boolean`: `true`, `false`, `1` or `0`. Anything else is not read.
fn boolean(node: &XmlNode<'_>, name: &str) -> Result<Option<bool>, DialogInfoError> {
    Ok(node.child_text(name)?.and_then(|text| match &*text {
        "true" | "1" => Some(true),
        "false" | "0" => Some(false),
        _ => None,
    }))
}

fn read_entries(node: Option<&XmlNode<'_>>) -> Result<Vec<UriEntry>, DialogInfoError> {
    let Some(node) = node else {
        return Ok(Vec::new());
    };
    bounded(
        node.children_named("entry").map(|entry| {
            Ok(UriEntry {
                uri: entry
                    .child_text("uri")?
                    .ok_or(DialogInfoError::Malformed("a URI entry with no uri"))?,
                display_text: entry.child_text("display-text")?,
                purpose: entry.child_text("purpose")?,
            })
        }),
        MAX_ENTRIES,
        "URI entries",
    )
}

fn read_description(node: &XmlNode<'_>) -> Result<ConferenceDescription, DialogInfoError> {
    let available_media =
        match node.child("available-media") {
            Some(list) => bounded(
                list.children_named("entry").map(|entry| {
                    Ok(AvailableMedia {
                        label: entry.attributes.text("label")?.ok_or(
                            DialogInfoError::Malformed("an available-media entry with no label"),
                        )?,
                        display_text: entry.child_text("display-text")?,
                        media_type: entry.child_text("type")?,
                        status: entry
                            .child_text("status")?
                            .map(|text| MediaStatus::read(&text)),
                    })
                }),
                MAX_ENTRIES,
                "available media",
            )?,
            None => Vec::new(),
        };
    Ok(ConferenceDescription {
        state: ElementState::read(node.attributes)?,
        display_text: node.child_text("display-text")?,
        subject: node.child_text("subject")?,
        free_text: node.child_text("free-text")?,
        keywords: node.child_text("keywords")?,
        conf_uris: read_entries(node.child("conf-uris"))?,
        service_uris: read_entries(node.child("service-uris"))?,
        maximum_user_count: number(node, "maximum-user-count")?,
        available_media,
    })
}

fn read_host(node: &XmlNode<'_>) -> Result<HostInfo, DialogInfoError> {
    Ok(HostInfo {
        state: ElementState::read(node.attributes)?,
        display_text: node.child_text("display-text")?,
        web_page: node.child_text("web-page")?,
        uris: read_entries(node.child("uris"))?,
    })
}

fn read_status(node: &XmlNode<'_>) -> Result<ConferenceStatus, DialogInfoError> {
    Ok(ConferenceStatus {
        state: ElementState::read(node.attributes)?,
        user_count: number(node, "user-count")?,
        active: boolean(node, "active")?,
        locked: boolean(node, "locked")?,
    })
}

fn read_users(node: &XmlNode<'_>) -> Result<Users, DialogInfoError> {
    Ok(Users {
        state: ElementState::read(node.attributes)?,
        users: bounded(
            node.children_named("user").map(read_user),
            MAX_USERS,
            "users",
        )?,
    })
}

fn read_user(node: &XmlNode<'_>) -> Result<User, DialogInfoError> {
    let roles = match node.child("roles") {
        Some(roles) => bounded(
            roles
                .children_named("entry")
                .map(|entry| entry.trimmed().map(Box::from)),
            MAX_ENTRIES,
            "roles",
        )?,
        None => Vec::new(),
    };
    Ok(User {
        state: ElementState::read(node.attributes)?,
        // §4.6 keys a user by it: one without it names nothing to merge into
        entity: node
            .attributes
            .text("entity")?
            .ok_or(DialogInfoError::Malformed("a user with no entity"))?,
        display_text: node.child_text("display-text")?,
        roles,
        endpoints: bounded(
            node.children_named("endpoint").map(read_endpoint),
            MAX_ENDPOINTS,
            "endpoints",
        )?,
    })
}

fn read_execution(node: Option<&XmlNode<'_>>) -> Result<Option<ExecutionInfo>, DialogInfoError> {
    node.map(|node| {
        Ok(ExecutionInfo {
            when: node.child_text("when")?,
            reason: node.child_text("reason")?,
            by: node.child_text("by")?,
        })
    })
    .transpose()
}

fn read_endpoint(node: &XmlNode<'_>) -> Result<Endpoint, DialogInfoError> {
    Ok(Endpoint {
        state: ElementState::read(node.attributes)?,
        entity: node
            .attributes
            .text("entity")?
            .ok_or(DialogInfoError::Malformed("an endpoint with no entity"))?,
        display_text: node.child_text("display-text")?,
        status: node
            .child_text("status")?
            .map(|text| EndpointStatus::read(&text)),
        joining_method: node
            .child_text("joining-method")?
            .map(|text| JoiningMethod::read(&text)),
        joining_info: read_execution(node.child("joining-info"))?,
        disconnection_method: node
            .child_text("disconnection-method")?
            .map(|text| DisconnectionMethod::read(&text)),
        disconnection_info: read_execution(node.child("disconnection-info"))?,
        media: bounded(
            node.children_named("media").map(read_media),
            MAX_MEDIA,
            "media",
        )?,
    })
}

fn read_media(node: &XmlNode<'_>) -> Result<Media, DialogInfoError> {
    Ok(Media {
        id: node
            .attributes
            .text("id")?
            .ok_or(DialogInfoError::Malformed("a media element with no id"))?,
        display_text: node.child_text("display-text")?,
        media_type: node.child_text("type")?,
        label: node.child_text("label")?,
        src_id: node.child_text("src-id")?,
        status: node
            .child_text("status")?
            .map(|text| MediaStatus::read(&text)),
    })
}

// -- merging (§4.6) ----------------------------------------------------------

/// A present value replaces the held one; an absent one leaves it alone.
fn take<T: Clone>(held: &mut Option<T>, update: Option<&T>) {
    if let Some(value) = update {
        *held = Some(value.clone());
    }
}

/// Something §4.6 matches by a key and merges field by field.
trait Keyed: Clone {
    fn key(&self) -> &str;
    /// What the document said about it. Elements the schema gives no `state`
    /// attribute are merged whenever they appear.
    fn state(&self) -> ElementState {
        ElementState::Partial
    }
    fn merge(&mut self, update: &Self);
    /// The value as held: every state `full`, nothing `deleted` left in it.
    fn settled(&self) -> Self {
        self.clone()
    }
}

/// Merge `updates` into `held` by key. A row not held is added even past the
/// list's bound: [`Conference::apply`] checks the bounds on the merged copy
/// and keeps none of it when one is passed.
fn merge_rows<T: Keyed>(held: &mut Vec<T>, updates: &[T]) {
    for update in updates {
        let at = held.iter().position(|row| row.key() == update.key());
        match (update.state(), at) {
            (ElementState::Deleted, Some(at)) => {
                held.remove(at);
            }
            (ElementState::Deleted, None) => (),
            (ElementState::Full, Some(at)) => {
                if let Some(row) = held.get_mut(at) {
                    *row = update.settled();
                }
            }
            (ElementState::Partial, Some(at)) => {
                if let Some(row) = held.get_mut(at) {
                    row.merge(update);
                }
            }
            (_, None) => held.push(update.settled()),
        }
    }
}

/// The rows of a list, settled: what a `full` element holds.
fn settled_rows<T: Keyed>(rows: &[T]) -> Vec<T> {
    rows.iter()
        .filter(|row| row.state() != ElementState::Deleted)
        .map(Keyed::settled)
        .collect()
}

impl Keyed for UriEntry {
    fn key(&self) -> &str {
        &self.uri
    }
    fn merge(&mut self, update: &Self) {
        take(&mut self.display_text, update.display_text.as_ref());
        take(&mut self.purpose, update.purpose.as_ref());
    }
}

impl Keyed for AvailableMedia {
    fn key(&self) -> &str {
        &self.label
    }
    fn merge(&mut self, update: &Self) {
        take(&mut self.display_text, update.display_text.as_ref());
        take(&mut self.media_type, update.media_type.as_ref());
        take(&mut self.status, update.status.as_ref());
    }
}

impl Keyed for Media {
    fn key(&self) -> &str {
        &self.id
    }
    fn merge(&mut self, update: &Self) {
        take(&mut self.display_text, update.display_text.as_ref());
        take(&mut self.media_type, update.media_type.as_ref());
        take(&mut self.label, update.label.as_ref());
        take(&mut self.src_id, update.src_id.as_ref());
        take(&mut self.status, update.status.as_ref());
    }
}

impl Keyed for Endpoint {
    fn key(&self) -> &str {
        &self.entity
    }
    fn state(&self) -> ElementState {
        self.state
    }
    fn merge(&mut self, update: &Self) {
        take(&mut self.display_text, update.display_text.as_ref());
        take(&mut self.status, update.status.as_ref());
        take(&mut self.joining_method, update.joining_method.as_ref());
        take(&mut self.joining_info, update.joining_info.as_ref());
        take(
            &mut self.disconnection_method,
            update.disconnection_method.as_ref(),
        );
        take(
            &mut self.disconnection_info,
            update.disconnection_info.as_ref(),
        );
        merge_rows(&mut self.media, &update.media);
    }
    fn settled(&self) -> Self {
        Self {
            state: ElementState::Full,
            ..self.clone()
        }
    }
}

impl Keyed for User {
    fn key(&self) -> &str {
        &self.entity
    }
    fn state(&self) -> ElementState {
        self.state
    }
    fn merge(&mut self, update: &Self) {
        take(&mut self.display_text, update.display_text.as_ref());
        // roles are a plain list of tokens, not keyed: present, they are the
        // whole list
        if !update.roles.is_empty() {
            self.roles.clone_from(&update.roles);
        }
        merge_rows(&mut self.endpoints, &update.endpoints);
    }
    fn settled(&self) -> Self {
        Self {
            state: ElementState::Full,
            endpoints: settled_rows(&self.endpoints),
            ..self.clone()
        }
    }
}

/// An element that is not keyed but carries a `state`: the three sections
/// of the document under its root.
trait Section: Clone {
    fn state(&self) -> ElementState;
    fn merge(&mut self, update: &Self);
    fn settled(&self) -> Self;
}

fn merge_section<T: Section>(held: &mut Option<T>, update: Option<&T>) {
    let Some(update) = update else {
        return;
    };
    match (update.state(), held.as_mut()) {
        (ElementState::Deleted, _) => *held = None,
        (ElementState::Partial, Some(section)) => section.merge(update),
        (ElementState::Full | ElementState::Partial, _) => *held = Some(update.settled()),
    }
}

impl Section for ConferenceDescription {
    fn state(&self) -> ElementState {
        self.state
    }
    fn merge(&mut self, update: &Self) {
        take(&mut self.display_text, update.display_text.as_ref());
        take(&mut self.subject, update.subject.as_ref());
        take(&mut self.free_text, update.free_text.as_ref());
        take(&mut self.keywords, update.keywords.as_ref());
        take(
            &mut self.maximum_user_count,
            update.maximum_user_count.as_ref(),
        );
        merge_rows(&mut self.conf_uris, &update.conf_uris);
        merge_rows(&mut self.service_uris, &update.service_uris);
        merge_rows(&mut self.available_media, &update.available_media);
    }
    fn settled(&self) -> Self {
        Self {
            state: ElementState::Full,
            ..self.clone()
        }
    }
}

impl Section for HostInfo {
    fn state(&self) -> ElementState {
        self.state
    }
    fn merge(&mut self, update: &Self) {
        take(&mut self.display_text, update.display_text.as_ref());
        take(&mut self.web_page, update.web_page.as_ref());
        merge_rows(&mut self.uris, &update.uris);
    }
    fn settled(&self) -> Self {
        Self {
            state: ElementState::Full,
            ..self.clone()
        }
    }
}

impl Section for ConferenceStatus {
    fn state(&self) -> ElementState {
        self.state
    }
    fn merge(&mut self, update: &Self) {
        take(&mut self.user_count, update.user_count.as_ref());
        take(&mut self.active, update.active.as_ref());
        take(&mut self.locked, update.locked.as_ref());
    }
    fn settled(&self) -> Self {
        Self {
            state: ElementState::Full,
            ..self.clone()
        }
    }
}

// -- what is held, weighed ---------------------------------------------------

/// What each element and each value costs on top of its text: less than the
/// markup of any of them (`<a/>`, `a=""`), so that a picture read from one
/// document never weighs more than the document did.
const MARKUP: usize = 4;

/// What holding something costs, counted in the bytes of the document it
/// would take to say it.
trait Weigh {
    fn weigh(&self) -> usize;
}

impl Weigh for Box<str> {
    fn weigh(&self) -> usize {
        MARKUP.saturating_add(self.len())
    }
}

impl<T: Weigh> Weigh for Option<T> {
    fn weigh(&self) -> usize {
        self.as_ref().map_or(0, Weigh::weigh)
    }
}

impl<T: Weigh> Weigh for Vec<T> {
    fn weigh(&self) -> usize {
        self.iter()
            .map(Weigh::weigh)
            .fold(MARKUP, usize::saturating_add)
    }
}

/// The sum of what `parts` weigh, and the element around them.
fn weigh_all(parts: &[&dyn Weigh]) -> usize {
    parts
        .iter()
        .map(|part| part.weigh())
        .fold(MARKUP, usize::saturating_add)
}

// a value the schema lists weighs nothing; one kept as written, its text

impl Weigh for MediaStatus {
    fn weigh(&self) -> usize {
        if let Self::Other(ref text) = *self {
            text.weigh()
        } else {
            0
        }
    }
}

impl Weigh for EndpointStatus {
    fn weigh(&self) -> usize {
        if let Self::Other(ref text) = *self {
            text.weigh()
        } else {
            0
        }
    }
}

impl Weigh for JoiningMethod {
    fn weigh(&self) -> usize {
        if let Self::Other(ref text) = *self {
            text.weigh()
        } else {
            0
        }
    }
}

impl Weigh for DisconnectionMethod {
    fn weigh(&self) -> usize {
        if let Self::Other(ref text) = *self {
            text.weigh()
        } else {
            0
        }
    }
}

impl Weigh for UriEntry {
    fn weigh(&self) -> usize {
        weigh_all(&[&self.uri, &self.display_text, &self.purpose])
    }
}

impl Weigh for AvailableMedia {
    fn weigh(&self) -> usize {
        weigh_all(&[
            &self.label,
            &self.display_text,
            &self.media_type,
            &self.status,
        ])
    }
}

impl Weigh for ExecutionInfo {
    fn weigh(&self) -> usize {
        weigh_all(&[&self.when, &self.reason, &self.by])
    }
}

impl Weigh for Media {
    fn weigh(&self) -> usize {
        weigh_all(&[
            &self.id,
            &self.display_text,
            &self.media_type,
            &self.label,
            &self.src_id,
            &self.status,
        ])
    }
}

impl Weigh for Endpoint {
    fn weigh(&self) -> usize {
        weigh_all(&[
            &self.entity,
            &self.display_text,
            &self.status,
            &self.joining_method,
            &self.joining_info,
            &self.disconnection_method,
            &self.disconnection_info,
            &self.media,
        ])
    }
}

impl Weigh for User {
    fn weigh(&self) -> usize {
        weigh_all(&[
            &self.entity,
            &self.display_text,
            &self.roles,
            &self.endpoints,
        ])
    }
}

impl Weigh for ConferenceDescription {
    fn weigh(&self) -> usize {
        weigh_all(&[
            &self.display_text,
            &self.subject,
            &self.free_text,
            &self.keywords,
            &self.conf_uris,
            &self.service_uris,
            &self.available_media,
        ])
    }
}

impl Weigh for HostInfo {
    fn weigh(&self) -> usize {
        weigh_all(&[&self.display_text, &self.web_page, &self.uris])
    }
}

impl Weigh for ConferenceStatus {
    fn weigh(&self) -> usize {
        MARKUP
    }
}

/// What one document did to a [`Conference`] (§4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConferenceUpdate {
    /// It was merged in.
    Applied,
    /// Its version is not newer than the one already applied, so it is late
    /// or repeated, and was discarded.
    Stale,
    /// It carries partial state and the version before it never arrived (or
    /// nothing has arrived yet), or merging it would hold more than one
    /// full-state document can carry, so it was not applied. A refresh gets
    /// full state back: [`UserAgent::request_full_state`]. (A conference too
    /// large for that is then refused by [`ConferenceInfo::parse`].)
    Resubscribe,
    /// It carries partial state while full state is already being asked
    /// for, so it was discarded without asking again.
    AwaitingFullState,
}

/// Everything one conference subscription has been told, merged (§4.6).
///
/// One per subscription: `version` numbers the documents of one
/// subscription, so when the user agent starts a fresh subscription under
/// the same handle (a [`crate::UaEvent::Subscribing`] after an end worth
/// retrying), start a fresh `Conference` with it.
#[derive(Clone, Debug, Default)]
pub struct Conference {
    entity: Option<Box<str>>,
    version: Option<u32>,
    awaiting_full: bool,
    description: Option<ConferenceDescription>,
    host: Option<HostInfo>,
    status: Option<ConferenceStatus>,
    users: Vec<User>,
}

impl Conference {
    /// Nothing known yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The conference's URI, once a document has named it.
    #[must_use]
    pub fn entity(&self) -> Option<&str> {
        self.entity.as_deref()
    }

    /// The last version applied.
    #[must_use]
    pub const fn version(&self) -> Option<u32> {
        self.version
    }

    /// Whether a gap was seen and full state has not arrived since.
    #[must_use]
    pub const fn is_awaiting_full_state(&self) -> bool {
        self.awaiting_full
    }

    /// `conference-description`, as held.
    #[must_use]
    pub const fn description(&self) -> Option<&ConferenceDescription> {
        self.description.as_ref()
    }

    /// `host-info`, as held.
    #[must_use]
    pub const fn host(&self) -> Option<&HostInfo> {
        self.host.as_ref()
    }

    /// `conference-state`, as held.
    #[must_use]
    pub const fn status(&self) -> Option<&ConferenceStatus> {
        self.status.as_ref()
    }

    /// The users, in the order they were first heard of.
    #[must_use]
    pub fn users(&self) -> &[User] {
        &self.users
    }

    /// One user, by `entity`.
    #[must_use]
    pub fn user(&self, entity: &str) -> Option<&User> {
        self.users.iter().find(|user| &*user.entity == entity)
    }

    /// Merge one document in (§4.6).
    pub fn apply(&mut self, document: &ConferenceInfo) -> ConferenceUpdate {
        // a version at or behind the one held is a notification that arrived
        // late or twice: nothing in it is newer than what is held
        if self.version.is_some_and(|held| document.version <= held) {
            return ConferenceUpdate::Stale;
        }
        if document.state == ElementState::Full {
            *self = Self {
                entity: Some(document.entity.clone()),
                version: Some(document.version),
                ..Self::default()
            };
            self.merge(document);
            return ConferenceUpdate::Applied;
        }
        // partial state is a change against the version just before it,
        // and against nothing else
        let follows = self
            .version
            .is_some_and(|held| document.version == held.saturating_add(1));
        if self.awaiting_full {
            return ConferenceUpdate::AwaitingFullState;
        }
        if !follows {
            self.awaiting_full = true;
            return ConferenceUpdate::Resubscribe;
        }
        // merged on a copy, kept only while it holds no more than one
        // full-state document could carry: every partial document is bounded,
        // but what they add up to is not, and a picture larger than any full
        // state this reads is not one the focus can ever confirm. Leaving out
        // the rows past a bound instead would keep a picture the focus never
        // had, with nothing to say so
        let mut merged = self.clone();
        merged.version = Some(document.version);
        merged.merge(document);
        if !merged.is_within_bounds() || merged.weigh() > MAX_BYTES {
            self.awaiting_full = true;
            return ConferenceUpdate::Resubscribe;
        }
        *self = merged;
        ConferenceUpdate::Applied
    }

    /// Merge a document's sections and users into what is held.
    fn merge(&mut self, document: &ConferenceInfo) {
        merge_section(&mut self.description, document.description.as_ref());
        merge_section(&mut self.host, document.host.as_ref());
        merge_section(&mut self.status, document.status.as_ref());
        if let Some(ref users) = document.users {
            match users.state {
                ElementState::Deleted => self.users.clear(),
                ElementState::Full => self.users = settled_rows(&users.users),
                ElementState::Partial => merge_rows(&mut self.users, &users.users),
            }
        }
    }

    /// Whether every list holds no more than one document may carry.
    fn is_within_bounds(&self) -> bool {
        let entries = |list: &[UriEntry]| list.len() <= MAX_ENTRIES;
        self.description.as_ref().is_none_or(|description| {
            entries(&description.conf_uris)
                && entries(&description.service_uris)
                && description.available_media.len() <= MAX_ENTRIES
        }) && self.host.as_ref().is_none_or(|host| entries(&host.uris))
            && self.users.len() <= MAX_USERS
            && self.users.iter().all(|user| {
                user.endpoints.len() <= MAX_ENDPOINTS
                    && user
                        .endpoints
                        .iter()
                        .all(|endpoint| endpoint.media.len() <= MAX_MEDIA)
            })
    }

    /// What everything held weighs.
    fn weigh(&self) -> usize {
        weigh_all(&[
            &self.entity,
            &self.description,
            &self.host,
            &self.status,
            &self.users,
        ])
    }

    /// Read a body and merge it in.
    ///
    /// # Errors
    /// [`ConferenceInfoError`], leaving everything held as it was.
    pub fn apply_body(&mut self, body: &[u8]) -> Result<ConferenceUpdate, ConferenceInfoError> {
        ConferenceInfo::parse(body).map(|document| self.apply(&document))
    }

    /// Merge in what a NOTIFY of a `conference` subscription carried — the
    /// `request` of [`crate::UaEvent::Notified`].
    ///
    /// `Ok(None)` for a NOTIFY with no body, which is what a pending
    /// subscription is usually told.
    ///
    /// # Errors
    /// [`ConferenceInfoError::NotConferenceInfo`] for a body of another
    /// type, and anything [`ConferenceInfo::parse`] refuses. Either way
    /// nothing held changes.
    pub fn apply_notify(
        &mut self,
        request: &OwnedMessage,
    ) -> Result<Option<ConferenceUpdate>, ConferenceInfoError> {
        let raw = request.as_raw();
        let body = raw.body();
        if body.is_empty() {
            return Ok(None);
        }
        if !raw
            .content_type()
            .is_ok_and(|kind| kind.is("application", "conference-info+xml"))
        {
            return Err(ConferenceInfoError::NotConferenceInfo);
        }
        self.apply_body(body).map(Some)
    }
}

// -- subscribing -------------------------------------------------------------

impl Subscribe {
    /// A subscription to the conference at `focus` (RFC 4575 §3): `Event:
    /// conference`, with `Accept: application/conference-info+xml` (§3.5),
    /// for [`crate::DEFAULT_EXPIRES`] — the hour §3.4 makes the default —
    /// unless [`Subscribe::expires`] says otherwise.
    #[must_use]
    pub fn conference(focus: Uri) -> Self {
        Self::new(focus, CONFERENCE_EVENT).accept(CONFERENCE_INFO_TYPE.as_bytes())
    }
}

impl UserAgent {
    /// Subscribe to a conference (RFC 4575 §3), kept alive like any other
    /// subscription by [`UserAgent::subscribe`].
    ///
    /// Every notification arrives as [`crate::UaEvent::Notified`]; feed its
    /// `request` to [`Conference::apply_notify`].
    ///
    /// # Errors
    /// [`UaError::NoSuchAccount`].
    pub fn subscribe_conference(
        &mut self,
        account: crate::AccountId,
        focus: Uri,
        now: Instant,
    ) -> Result<SubscriptionHandle, UaError> {
        self.subscribe(account, &Subscribe::conference(focus), now)
    }

    /// Refresh a subscription now, so that the notification answering it
    /// carries full state: what [`ConferenceUpdate::Resubscribe`] asks for
    /// (RFC 4575 §4.6), and what RFC 6665 §4.2.1 makes the NOTIFY after a
    /// refresh carry.
    ///
    /// A subscription whose dialog is not open yet is started again instead,
    /// which gets full state the same way.
    ///
    /// # Errors
    /// [`UaError::NoSuchSubscription`].
    pub fn request_full_state(
        &mut self,
        subscription: SubscriptionHandle,
        now: Instant,
    ) -> Result<(), UaError> {
        if !self.subscriptions.contains_key(&subscription) {
            return Err(UaError::NoSuchSubscription);
        }
        self.refresh_subscription(subscription, now);
        self.drain(now);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;
    use std::net::SocketAddr;
    use std::time::Instant;

    use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, RawMessage, parse};

    use super::{
        Conference, ConferenceInfo, ConferenceInfoError, ConferenceUpdate, DisconnectionMethod,
        ElementState, EndpointStatus, JoiningMethod, MAX_BYTES, MAX_DEPTH, MAX_USERS, MediaStatus,
    };
    use crate::account::Account;
    use crate::agent::UserAgent;
    use crate::event::UaEvent;
    use crate::subscription::SubscriptionHandle;
    use crate::{EndpointConfig, Input, TransportId, TransportProtocol, UaError, Uri};

    /// The full-state example of RFC 4575 §6, as the RFC lays it out:
    /// comments between the sections, two users, one of whom has left.
    const FULL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<conference-info
    xmlns="urn:ietf:params:xml:ns:conference-info"
    entity="sips:conf233@example.com"
    state="full" version="1">
  <!--
    CONFERENCE INFO
  -->
  <conference-description>
    <subject>Agenda: This month's goals</subject>
    <conf-uris>
      <entry>
        <uri>sips:conf233@example.com</uri>
        <display-text>Conference Bridge</display-text>
        <purpose>participation</purpose>
      </entry>
    </conf-uris>
    <service-uris>
      <entry>
        <uri>http://www.example.com/conf233/</uri>
        <purpose>web-page</purpose>
      </entry>
    </service-uris>
  </conference-description>
  <!--
    CONFERENCE STATE
  -->
  <conference-state>
    <user-count>33</user-count>
  </conference-state>
  <!--
    USERS
  -->
  <users>
    <user entity="sip:bob@example.com" state="full">
      <display-text>Bob Hoskins</display-text>
      <!--
        ENDPOINTS
      -->
      <endpoint entity="sip:bob@pc33.example.com">
        <display-text>Bob's Laptop</display-text>
        <status>disconnected</status>
        <disconnection-method>departed</disconnection-method>
        <disconnection-info>
          <when>2005-03-04T20:00:00Z</when>
          <reason>bad voice quality</reason>
          <by>sip:mike@example.com</by>
        </disconnection-info>
        <!--
          MEDIA
        -->
        <media id="1">
          <display-text>main audio</display-text>
          <type>audio</type>
          <label>34567</label>
          <src-id>432424</src-id>
          <status>sendrecv</status>
        </media>
      </endpoint>
    </user>
    <!--
      USER
    -->
    <user entity="sip:alice@example.com" state="full">
      <display-text>Alice</display-text>
      <!--
        ENDPOINTS
      -->
      <endpoint entity="sip:4kfk4j392jsu@example.com;grid=433kj4j3u">
        <status>connected</status>
        <joining-method>dialed-out</joining-method>
        <joining-info>
          <when>2005-03-04T20:00:00Z</when>
          <by>sip:mike@example.com</by>
        </joining-info>
        <!--
          MEDIA
        -->
        <media id="1">
          <type>audio</type>
          <label>34566</label>
          <src-id>534232</src-id>
          <status>sendrecv</status>
        </media>
      </endpoint>
    </user>
  </users>
</conference-info>"#;

    fn document(body: &str) -> ConferenceInfo {
        ConferenceInfo::parse(body.as_bytes()).expect("a conference-info document")
    }

    /// A partial document around `users`, at `version`.
    fn partial(version: u32, users: &str) -> String {
        format!(
            "<conference-info xmlns=\"urn:ietf:params:xml:ns:conference-info\" \
entity=\"sips:conf233@example.com\" state=\"partial\" version=\"{version}\">\
<users state=\"partial\">{users}</users></conference-info>"
        )
    }

    fn held() -> Conference {
        let mut conference = Conference::new();
        assert_eq!(conference.apply(&document(FULL)), ConferenceUpdate::Applied);
        conference
    }

    #[test]
    fn the_rfcs_full_example_reads_as_the_rfc_describes_it() {
        let info = document(FULL);
        assert_eq!(&*info.entity, "sips:conf233@example.com");
        assert_eq!(info.version, 1);
        assert_eq!(info.state, ElementState::Full);

        let description = info.description.as_ref().expect("a description");
        assert_eq!(
            description.subject.as_deref(),
            Some("Agenda: This month's goals")
        );
        assert_eq!(&*description.conf_uris[0].uri, "sips:conf233@example.com");
        assert_eq!(
            description.conf_uris[0].purpose.as_deref(),
            Some("participation")
        );
        assert_eq!(
            description.service_uris[0].purpose.as_deref(),
            Some("web-page")
        );
        assert_eq!(info.status.as_ref().and_then(|s| s.user_count), Some(33));

        let users = &info.users.as_ref().expect("users").users;
        assert_eq!(users.len(), 2);
        let bob = &users[0];
        assert_eq!(bob.display_text.as_deref(), Some("Bob Hoskins"));
        let laptop = &bob.endpoints[0];
        assert_eq!(laptop.display_text.as_deref(), Some("Bob's Laptop"));
        assert_eq!(laptop.status, Some(EndpointStatus::Disconnected));
        assert_eq!(
            laptop.disconnection_method,
            Some(DisconnectionMethod::Departed)
        );
        let why = laptop.disconnection_info.as_ref().expect("the details");
        assert_eq!(why.reason.as_deref(), Some("bad voice quality"));
        assert_eq!(why.by.as_deref(), Some("sip:mike@example.com"));
        assert_eq!(&*laptop.media[0].id, "1");
        assert_eq!(laptop.media[0].media_type.as_deref(), Some("audio"));
        assert_eq!(laptop.media[0].label.as_deref(), Some("34567"));
        assert_eq!(laptop.media[0].src_id.as_deref(), Some("432424"));
        assert_eq!(laptop.media[0].status, Some(MediaStatus::SendRecv));

        let alice = &users[1].endpoints[0];
        assert_eq!(
            &*alice.entity,
            "sip:4kfk4j392jsu@example.com;grid=433kj4j3u"
        );
        assert_eq!(alice.status, Some(EndpointStatus::Connected));
        assert_eq!(alice.joining_method, Some(JoiningMethod::DialedOut));
        assert_eq!(
            alice
                .joining_info
                .as_ref()
                .and_then(|info| info.when.as_deref()),
            Some("2005-03-04T20:00:00Z")
        );
    }

    #[test]
    fn a_partial_document_merges_by_key_and_deletes_what_it_marks_deleted() {
        let mut conference = held();
        let update = partial(
            2,
            "<user entity=\"sip:bob@example.com\" state=\"partial\">\
<endpoint entity=\"sip:bob@pc33.example.com\" state=\"partial\">\
<status>connected</status><media id=\"1\"><status>recvonly</status></media>\
</endpoint></user>\
<user entity=\"sip:alice@example.com\" state=\"deleted\"/>\
<user entity=\"sip:carol@example.com\" state=\"full\"><display-text>Carol</display-text>\
<endpoint entity=\"sip:carol@example.com\"><status>alerting</status></endpoint></user>",
        );
        assert_eq!(
            conference.apply(&document(&update)),
            ConferenceUpdate::Applied
        );
        assert_eq!(conference.version(), Some(2));

        let bob = conference.user("sip:bob@example.com").expect("bob");
        assert_eq!(
            bob.display_text.as_deref(),
            Some("Bob Hoskins"),
            "what the update left out is kept"
        );
        let laptop = &bob.endpoints[0];
        assert_eq!(laptop.status, Some(EndpointStatus::Connected));
        assert_eq!(
            laptop.display_text.as_deref(),
            Some("Bob's Laptop"),
            "a partial endpoint keeps its other fields"
        );
        assert_eq!(laptop.media[0].status, Some(MediaStatus::RecvOnly));
        assert_eq!(
            laptop.media[0].label.as_deref(),
            Some("34567"),
            "a media stream is merged by id, not replaced"
        );

        assert!(conference.user("sip:alice@example.com").is_none());
        let carol = conference.user("sip:carol@example.com").expect("carol");
        assert_eq!(carol.endpoints[0].status, Some(EndpointStatus::Alerting));
        assert_eq!(carol.state, ElementState::Full);
        assert_eq!(
            conference.users().len(),
            2,
            "the rest of the table is untouched"
        );
        assert_eq!(
            conference.status().and_then(|status| status.user_count),
            Some(33),
            "a section the document does not mention stays as it was"
        );
    }

    #[test]
    fn a_full_element_inside_a_partial_document_replaces_what_was_held() {
        let mut conference = held();
        let update = partial(
            2,
            "<user entity=\"sip:bob@example.com\" state=\"full\">\
<endpoint entity=\"sip:bob@phone.example.com\"><status>connected</status></endpoint></user>",
        );
        conference.apply(&document(&update));
        let bob = conference.user("sip:bob@example.com").expect("bob");
        assert_eq!(
            bob.display_text, None,
            "a full user brings only what it says"
        );
        assert_eq!(bob.endpoints.len(), 1);
        assert_eq!(&*bob.endpoints[0].entity, "sip:bob@phone.example.com");
    }

    #[test]
    fn a_partial_section_changes_only_the_values_it_carries() {
        let mut conference = held();
        let update = "<conference-info entity=\"sips:conf233@example.com\" state=\"partial\" \
version=\"2\"><conference-state state=\"partial\"><user-count>34</user-count>\
<locked>true</locked></conference-state><conference-description state=\"partial\">\
<conf-uris><entry><uri>sips:conf233@example.com</uri><display-text>Bridge</display-text>\
</entry><entry><uri>tel:+15551234</uri></entry></conf-uris></conference-description>\
</conference-info>";
        assert_eq!(
            conference.apply(&document(update)),
            ConferenceUpdate::Applied
        );
        let status = conference.status().expect("a state");
        assert_eq!(status.user_count, Some(34));
        assert_eq!(status.locked, Some(true));
        let description = conference.description().expect("a description");
        assert_eq!(
            description.subject.as_deref(),
            Some("Agenda: This month's goals")
        );
        assert_eq!(description.conf_uris.len(), 2);
        assert_eq!(
            description.conf_uris[0].display_text.as_deref(),
            Some("Bridge")
        );
        assert_eq!(
            description.conf_uris[0].purpose.as_deref(),
            Some("participation"),
            "an entry is merged by its uri"
        );
        assert_eq!(conference.users().len(), 2);
    }

    #[test]
    fn a_partial_user_changes_its_roles_only_when_it_lists_them() {
        let mut conference = held();
        let with_roles = partial(
            2,
            "<user entity=\"sip:bob@example.com\" state=\"partial\">\
<roles><entry>participant</entry></roles></user>",
        );
        conference.apply(&document(&with_roles));
        let without = partial(
            3,
            "<user entity=\"sip:bob@example.com\" state=\"partial\">\
<display-text>Robert</display-text></user>",
        );
        assert_eq!(
            conference.apply(&document(&without)),
            ConferenceUpdate::Applied
        );
        let bob = conference.user("sip:bob@example.com").expect("bob");
        assert_eq!(bob.display_text.as_deref(), Some("Robert"));
        assert_eq!(
            bob.roles,
            vec![Box::<str>::from("participant")],
            "roles not mentioned are kept"
        );
        let replaced = partial(
            4,
            "<user entity=\"sip:bob@example.com\" state=\"partial\">\
<roles><entry>moderator</entry></roles></user>",
        );
        conference.apply(&document(&replaced));
        assert_eq!(
            conference.user("sip:bob@example.com").expect("bob").roles,
            vec![Box::<str>::from("moderator")],
            "roles are not keyed: listed, they are the whole list"
        );
    }

    #[test]
    fn a_full_user_holds_none_of_the_endpoints_it_marks_deleted() {
        let mut conference = held();
        let update = partial(
            2,
            "<user entity=\"sip:bob@example.com\" state=\"full\">\
<endpoint entity=\"sip:bob@pc33.example.com\" state=\"deleted\"/>\
<endpoint entity=\"sip:bob@phone.example.com\"/></user>",
        );
        assert_eq!(
            conference.apply(&document(&update)),
            ConferenceUpdate::Applied
        );
        let bob = conference.user("sip:bob@example.com").expect("bob");
        assert_eq!(bob.endpoints.len(), 1);
        assert_eq!(&*bob.endpoints[0].entity, "sip:bob@phone.example.com");
        assert_eq!(bob.endpoints[0].state, ElementState::Full);
    }

    #[test]
    fn a_deleted_users_element_empties_the_table() {
        let mut conference = held();
        let update = "<conference-info entity=\"sips:conf233@example.com\" state=\"partial\" \
version=\"2\"><users state=\"deleted\"/></conference-info>";
        assert_eq!(
            conference.apply(&document(update)),
            ConferenceUpdate::Applied
        );
        assert!(conference.users().is_empty());
        assert!(conference.description().is_some());
    }

    #[test]
    fn text_past_the_bound_is_refused_however_it_is_split() {
        // each piece is under the tokeniser's own bound; together they are not
        let piece = "x".repeat(1_000);
        let body = format!(
            "<conference-info entity=\"sip:c@example.com\" version=\"1\">\
<conference-description><subject>{piece}<!---->{piece}<!---->{piece}<!---->{piece}\
<!---->{piece}</subject></conference-description></conference-info>"
        );
        assert_eq!(
            ConferenceInfo::parse(body.as_bytes()),
            Err(ConferenceInfoError::TooLarge("element content"))
        );
        let four = format!(
            "<conference-info entity=\"sip:c@example.com\" version=\"1\">\
<conference-description><subject>{piece}<!---->{piece}<!---->{piece}<!---->{piece}\
</subject></conference-description></conference-info>"
        );
        let subject = document(&four)
            .description
            .and_then(|description| description.subject)
            .expect("a subject");
        assert_eq!(subject.len(), 4_000);
    }

    #[test]
    fn a_deleted_section_is_gone() {
        let mut conference = held();
        let update = "<conference-info entity=\"sips:conf233@example.com\" state=\"partial\" \
version=\"2\"><conference-description state=\"deleted\"/></conference-info>";
        conference.apply(&document(update));
        assert!(conference.description().is_none());
        assert!(conference.status().is_some());
    }

    #[test]
    fn a_version_not_newer_than_the_held_one_is_discarded() {
        let mut conference = held();
        assert_eq!(conference.apply(&document(FULL)), ConferenceUpdate::Stale);
        let mut update = partial(
            2,
            "<user entity=\"sip:dave@example.com\"><display-text>Dave</display-text></user>",
        );
        assert_eq!(
            conference.apply(&document(&update)),
            ConferenceUpdate::Applied
        );
        // the same version again, now carrying something else: late, and not
        // allowed to overwrite what was merged after it
        update = partial(
            2,
            "<user entity=\"sip:bob@example.com\" state=\"deleted\"/>",
        );
        assert_eq!(
            conference.apply(&document(&update)),
            ConferenceUpdate::Stale
        );
        assert!(conference.user("sip:bob@example.com").is_some());
        assert_eq!(conference.version(), Some(2));
    }

    #[test]
    fn a_lost_partial_notification_asks_for_full_state_once_and_holds_the_rest() {
        let mut conference = held();
        let skipped = partial(
            3,
            "<user entity=\"sip:bob@example.com\" state=\"deleted\"/>",
        );
        assert_eq!(
            conference.apply(&document(&skipped)),
            ConferenceUpdate::Resubscribe
        );
        assert!(conference.is_awaiting_full_state());
        assert!(
            conference.user("sip:bob@example.com").is_some(),
            "a delta on the wrong base is not merged"
        );
        assert_eq!(conference.version(), Some(1));

        let next = partial(
            4,
            "<user entity=\"sip:alice@example.com\" state=\"deleted\"/>",
        );
        assert_eq!(
            conference.apply(&document(&next)),
            ConferenceUpdate::AwaitingFullState
        );
        assert!(conference.user("sip:alice@example.com").is_some());

        let full = FULL.replace("version=\"1\"", "version=\"5\"");
        assert_eq!(
            conference.apply(&document(&full)),
            ConferenceUpdate::Applied
        );
        assert!(!conference.is_awaiting_full_state());
        assert_eq!(conference.version(), Some(5));
        let after = partial(
            6,
            "<user entity=\"sip:alice@example.com\" state=\"deleted\"/>",
        );
        assert_eq!(
            conference.apply(&document(&after)),
            ConferenceUpdate::Applied
        );
        assert!(conference.user("sip:alice@example.com").is_none());
    }

    #[test]
    fn partial_state_with_nothing_held_asks_for_full_state() {
        let mut conference = Conference::new();
        let first = partial(7, "<user entity=\"sip:bob@example.com\"/>");
        assert_eq!(
            conference.apply(&document(&first)),
            ConferenceUpdate::Resubscribe
        );
        assert!(conference.users().is_empty());
        assert_eq!(conference.version(), None);
    }

    #[test]
    fn full_state_replaces_everything_held() {
        let mut conference = held();
        let full = "<conference-info entity=\"sips:conf233@example.com\" state=\"full\" \
version=\"2\"><users><user entity=\"sip:erin@example.com\"/></users></conference-info>";
        assert_eq!(conference.apply(&document(full)), ConferenceUpdate::Applied);
        assert_eq!(conference.users().len(), 1);
        assert!(conference.description().is_none());
        assert!(conference.status().is_none());
    }

    #[test]
    fn a_document_missing_what_ordering_needs_is_refused() {
        for (body, expected) in [
            (
                "<conference-info entity=\"sip:c@example.com\"/>",
                ConferenceInfoError::Malformed("no version"),
            ),
            (
                "<conference-info version=\"1\"/>",
                ConferenceInfoError::Malformed("no entity"),
            ),
            (
                "<conference-info entity=\"sip:c@example.com\" version=\"1\" state=\"deleted\"/>",
                ConferenceInfoError::Malformed("a document is full or partial"),
            ),
            (
                "<conference-info entity=\"sip:c@example.com\" version=\"1\" state=\"most\"/>",
                ConferenceInfoError::Malformed("state is not full, partial or deleted"),
            ),
            (
                "<dialog-info version=\"1\"/>",
                ConferenceInfoError::NotConferenceInfo,
            ),
            (
                "<conference-info entity=\"sip:c@example.com\" version=\"1\">\
<users><user><display-text>x</display-text></user></users></conference-info>",
                ConferenceInfoError::Malformed("a user with no entity"),
            ),
            (
                "<conference-info entity=\"sip:c@example.com\" version=\"1\">\
<users><user entity=\"sip:u@example.com\"><endpoint entity=\"sip:u@example.com\">\
<media><type>audio</type></media></endpoint></user></users></conference-info>",
                ConferenceInfoError::Malformed("a media element with no id"),
            ),
        ] {
            assert_eq!(
                ConferenceInfo::parse(body.as_bytes()),
                Err(expected),
                "{body}"
            );
        }
    }

    #[test]
    fn what_the_dialog_info_reader_refuses_is_refused_here_too() {
        let doctype = "<?xml version=\"1.0\"?><!DOCTYPE conference-info [<!ENTITY a \"b\">]>\
<conference-info entity=\"sip:c@example.com\" version=\"1\"/>";
        assert_eq!(
            ConferenceInfo::parse(doctype.as_bytes()),
            Err(ConferenceInfoError::Refused(
                "a declaration or CDATA section"
            ))
        );
        let entity = "<conference-info entity=\"&x;\" version=\"1\"/>";
        assert_eq!(
            ConferenceInfo::parse(entity.as_bytes()),
            Err(ConferenceInfoError::Refused("an entity reference"))
        );
        let crossed = "<conference-info entity=\"sip:c@example.com\" version=\"1\">\
<users></conference-info></users>";
        assert_eq!(
            ConferenceInfo::parse(crossed.as_bytes()),
            Err(ConferenceInfoError::Malformed("closing tag does not match"))
        );
        let unclosed = "<conference-info entity=\"sip:c@example.com\" version=\"1\"><users>";
        assert_eq!(
            ConferenceInfo::parse(unclosed.as_bytes()),
            Err(ConferenceInfoError::Malformed("an element never closed"))
        );
        let trailing = "<conference-info entity=\"sip:c@example.com\" version=\"1\"/><users/>";
        assert_eq!(
            ConferenceInfo::parse(trailing.as_bytes()),
            Err(ConferenceInfoError::Malformed(
                "markup after the root element"
            ))
        );
    }

    #[test]
    fn nesting_past_the_bound_is_refused() {
        let mut body = String::from("<conference-info entity=\"sip:c@example.com\" version=\"1\">");
        for _ in 0..MAX_DEPTH {
            body.push_str("<x>");
        }
        assert_eq!(
            ConferenceInfo::parse(body.as_bytes()),
            Err(ConferenceInfoError::TooLarge("nesting"))
        );
    }

    #[test]
    fn more_users_than_the_bound_are_refused() {
        let mut body =
            String::from("<conference-info entity=\"sip:c@example.com\" version=\"1\"><users>");
        for n in 0..=MAX_USERS {
            write!(body, "<user entity=\"sip:{n}@example.com\"/>").expect("a string");
        }
        body.push_str("</users></conference-info>");
        assert_eq!(
            ConferenceInfo::parse(body.as_bytes()),
            Err(ConferenceInfoError::TooLarge("users"))
        );
    }

    #[test]
    fn a_partial_notification_adding_past_a_bound_is_not_merged_short() {
        let mut body = String::from(
            "<conference-info entity=\"sip:c@example.com\" state=\"full\" version=\"1\"><users>",
        );
        for n in 0..MAX_USERS {
            write!(body, "<user entity=\"sip:{n}@example.com\"/>").expect("a string");
        }
        body.push_str("</users></conference-info>");
        let mut conference = Conference::new();
        assert_eq!(
            conference.apply(&document(&body)),
            ConferenceUpdate::Applied
        );
        // a user the focus added, which there is no room to hold: merging
        // the rest and leaving it out would be a picture the focus never had
        let more = "<conference-info entity=\"sip:c@example.com\" state=\"partial\" version=\"2\">\
<users state=\"partial\"><user entity=\"sip:0@example.com\"><display-text>Zero</display-text>\
</user><user entity=\"sip:one-more@example.com\"/></users></conference-info>";
        assert_eq!(
            conference.apply(&document(more)),
            ConferenceUpdate::Resubscribe
        );
        assert_eq!(conference.version(), Some(1));
        assert_eq!(conference.users().len(), MAX_USERS);
        assert_eq!(
            conference
                .user("sip:0@example.com")
                .and_then(|user| user.display_text.as_deref()),
            None,
            "nothing of it is merged"
        );
    }

    /// The text a conference holds in its users, counted from what it shows.
    fn held_text(conference: &Conference) -> usize {
        let text = |value: &Option<Box<str>>| value.as_deref().map_or(0, str::len);
        conference
            .users()
            .iter()
            .map(|user| {
                user.entity.len()
                    + text(&user.display_text)
                    + user.roles.iter().map(|role| role.len()).sum::<usize>()
                    + user
                        .endpoints
                        .iter()
                        .map(|endpoint| {
                            endpoint.entity.len()
                                + text(&endpoint.display_text)
                                + endpoint
                                    .media
                                    .iter()
                                    .map(|media| media.id.len() + text(&media.display_text))
                                    .sum::<usize>()
                        })
                        .sum::<usize>()
            })
            .sum()
    }

    #[test]
    fn partial_notifications_cannot_grow_the_conference_past_one_full_document() {
        assert!(
            held().weigh() <= FULL.len(),
            "what one document holds weighs no more than the document"
        );
        let mut conference = Conference::new();
        let empty =
            "<conference-info entity=\"sips:conf233@example.com\" state=\"full\" version=\"1\"/>";
        assert_eq!(
            conference.apply(&document(empty)),
            ConferenceUpdate::Applied
        );
        let long = "x".repeat(990);
        let mut outcome = Vec::new();
        for version in 2..12_u32 {
            let mut users = String::new();
            for n in 0..100 {
                write!(
                    users,
                    "<user entity=\"sip:{version}-{n}-{long}@example.com\">\
<display-text>{long}</display-text></user>"
                )
                .expect("a string");
            }
            let body = partial(version, &users);
            assert!(
                body.len() <= MAX_BYTES,
                "each document is one a focus may send"
            );
            outcome.push(conference.apply(&document(&body)));
            assert!(
                held_text(&conference) <= MAX_BYTES,
                "version {version}: {} bytes held",
                held_text(&conference)
            );
        }
        // the second batch would hold more than any full-state document
        // could carry: the picture is not one the focus can confirm, so it
        // is not merged, and full state is asked for
        assert_eq!(outcome[0], ConferenceUpdate::Applied);
        assert_eq!(outcome[1], ConferenceUpdate::Resubscribe);
        assert!(
            outcome[2..]
                .iter()
                .all(|update| *update == ConferenceUpdate::AwaitingFullState)
        );
        assert_eq!(conference.version(), Some(2));
        assert_eq!(conference.users().len(), 100);
    }

    #[test]
    fn a_failed_document_leaves_the_conference_as_it_was() {
        let mut conference = held();
        assert!(conference.apply_body(b"<conference-info").is_err());
        assert_eq!(conference.version(), Some(1));
        assert_eq!(conference.users().len(), 2);
    }

    #[test]
    fn values_the_schema_does_not_list_are_kept_as_written() {
        let body = "<conference-info entity=\"sip:c@example.com\" version=\"1\"><users>\
<user entity=\"sip:u@example.com\"><endpoint entity=\"sip:u@example.com\">\
<status>thinking</status><joining-method>teleported</joining-method>\
<disconnection-method>evaporated</disconnection-method>\
<media id=\"v\"><status>sideways</status></media></endpoint></user></users>\
<conference-state><active>true</active><locked>0</locked><user-count>many</user-count>\
</conference-state></conference-info>";
        let info = document(body);
        let endpoint = &info.users.as_ref().expect("users").users[0].endpoints[0];
        assert_eq!(
            endpoint.status,
            Some(EndpointStatus::Other("thinking".into()))
        );
        assert_eq!(
            endpoint.joining_method,
            Some(JoiningMethod::Other("teleported".into()))
        );
        assert_eq!(
            endpoint.disconnection_method,
            Some(DisconnectionMethod::Other("evaporated".into()))
        );
        assert_eq!(
            endpoint.media[0].status,
            Some(MediaStatus::Other("sideways".into()))
        );
        let status = info.status.expect("a state");
        assert_eq!(status.active, Some(true));
        assert_eq!(status.locked, Some(false));
        assert_eq!(
            status.user_count, None,
            "a count that is not one is not read"
        );
    }

    // -- through the user agent ----------------------------------------------

    const UDP: TransportId = TransportId(1);

    fn local() -> SocketAddr {
        "192.0.2.1:5060".parse().expect("an address")
    }

    fn focus() -> SocketAddr {
        "192.0.2.9:5060".parse().expect("an address")
    }

    fn uri(text: &str) -> Uri {
        Uri::parse_str(text).expect("a URI")
    }

    fn agent(now: Instant) -> (UserAgent, crate::AccountId) {
        let mut agent = UserAgent::new(EndpointConfig::default(), [21; 32]).expect("an agent");
        agent
            .receive(
                Input::TransportBound {
                    transport: UDP,
                    protocol: TransportProtocol::Udp,
                    local: local(),
                    remote: None,
                },
                now,
            )
            .expect("binding a transport");
        let account = agent.add_account(Account::new(
            uri("sip:alice@example.com"),
            uri("sip:example.com"),
            uri("sip:alice@192.0.2.1"),
            UDP,
            focus(),
        ));
        (agent, account)
    }

    fn sent(agent: &mut UserAgent) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(transmit) = agent.poll_transmit() {
            out.push(transmit.payload.to_vec());
        }
        out
    }

    fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
        let mut scratch = ParseScratch::new();
        f(&parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message"))
    }

    fn header(bytes: &[u8], name: HeaderName<'_>) -> String {
        with(bytes, |message| {
            String::from_utf8_lossy(message.header(name).unwrap_or_default()).into_owned()
        })
    }

    fn deliver(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
        agent
            .receive(
                Input::Datagram {
                    transport: UDP,
                    remote: focus(),
                    local: local(),
                    data: bytes,
                },
                now,
            )
            .expect("a datagram");
    }

    fn accepted(subscribe: &[u8]) -> Vec<u8> {
        format!(
            "SIP/2.0 200 OK\r\nVia: {}\r\nFrom: {}\r\nTo: {};tag=focus\r\nCall-ID: {}\r\n\
CSeq: {}\r\nExpires: 3600\r\nContact: <sip:focus@192.0.2.9>\r\nContent-Length: 0\r\n\r\n",
            header(subscribe, HeaderName::Via),
            header(subscribe, HeaderName::From),
            header(subscribe, HeaderName::To),
            header(subscribe, HeaderName::CallId),
            header(subscribe, HeaderName::CSeq),
        )
        .into_bytes()
    }

    fn notify(subscribe: &[u8], cseq: u32, kind: &str, body: &str) -> Vec<u8> {
        format!(
            "NOTIFY sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKconf{cseq}\r\nMax-Forwards: 70\r\n\
From: {};tag=focus\r\nTo: {}\r\nCall-ID: {}\r\nCSeq: {cseq} NOTIFY\r\n\
Contact: <sip:focus@192.0.2.9>\r\nEvent: conference\r\n\
Subscription-State: active;expires=3600\r\nContent-Type: {kind}\r\n\
Content-Length: {}\r\n\r\n{body}",
            header(subscribe, HeaderName::To),
            header(subscribe, HeaderName::From),
            header(subscribe, HeaderName::CallId),
            body.len()
        )
        .into_bytes()
    }

    /// The `request` of every `Notified` the agent raised.
    fn notified(agent: &mut UserAgent) -> Vec<sipral_core::msg::OwnedMessage> {
        let mut out = Vec::new();
        while let Some(event) = agent.poll_event() {
            if let UaEvent::Notified { request, .. } = event {
                out.push(request);
            }
        }
        out
    }

    fn only_subscribe(all: &[Vec<u8>]) -> Vec<u8> {
        let subscribes: Vec<&Vec<u8>> = all
            .iter()
            .filter(|bytes| bytes.starts_with(b"SUBSCRIBE "))
            .collect();
        assert_eq!(subscribes.len(), 1, "exactly one SUBSCRIBE");
        subscribes[0].clone()
    }

    #[test]
    fn a_conference_subscription_names_the_package_and_its_body_type() {
        let t0 = Instant::now();
        let (mut agent, account) = agent(t0);
        agent
            .subscribe_conference(account, uri("sips:conf233@example.com"), t0)
            .expect("the SUBSCRIBE goes");
        let subscribe = only_subscribe(&sent(&mut agent));
        assert!(subscribe.starts_with(b"SUBSCRIBE sips:conf233@example.com SIP/2.0\r\n"));
        assert_eq!(header(&subscribe, HeaderName::Event), "conference");
        assert_eq!(
            header(&subscribe, HeaderName::Accept),
            "application/conference-info+xml"
        );
        assert_eq!(header(&subscribe, HeaderName::Expires), "3600");
    }

    #[test]
    fn notifications_build_the_conference_and_a_gap_refreshes_the_subscription() {
        let t0 = Instant::now();
        let (mut agent, account) = agent(t0);
        let handle = agent
            .subscribe_conference(account, uri("sips:conf233@example.com"), t0)
            .expect("the SUBSCRIBE goes");
        let subscribe = only_subscribe(&sent(&mut agent));
        deliver(&mut agent, &accepted(&subscribe), t0);
        deliver(
            &mut agent,
            &notify(&subscribe, 1, "application/conference-info+xml", FULL),
            t0,
        );
        sent(&mut agent);

        let mut conference = Conference::new();
        let requests = notified(&mut agent);
        assert_eq!(requests.len(), 1);
        assert_eq!(
            conference.apply_notify(&requests[0]),
            Ok(Some(ConferenceUpdate::Applied))
        );
        assert_eq!(conference.users().len(), 2);

        let gap = partial(
            3,
            "<user entity=\"sip:bob@example.com\" state=\"deleted\"/>",
        );
        deliver(
            &mut agent,
            &notify(&subscribe, 2, "application/conference-info+xml", &gap),
            t0,
        );
        sent(&mut agent);
        let requests = notified(&mut agent);
        assert_eq!(
            conference.apply_notify(&requests[0]),
            Ok(Some(ConferenceUpdate::Resubscribe))
        );
        agent
            .request_full_state(handle, t0)
            .expect("the subscription is there");
        let refresh = only_subscribe(&sent(&mut agent));
        assert_eq!(header(&refresh, HeaderName::Event), "conference");
        assert_eq!(header(&refresh, HeaderName::CSeq), "2 SUBSCRIBE");
        assert_eq!(
            header(&refresh, HeaderName::CallId),
            header(&subscribe, HeaderName::CallId),
            "a refresh in the same dialog, not a new subscription"
        );
        assert!(header(&refresh, HeaderName::To).contains("tag=focus"));
    }

    #[test]
    fn a_notify_of_another_body_type_or_none_is_not_merged() {
        let t0 = Instant::now();
        let (mut agent, account) = agent(t0);
        agent
            .subscribe_conference(account, uri("sips:conf233@example.com"), t0)
            .expect("the SUBSCRIBE goes");
        let subscribe = only_subscribe(&sent(&mut agent));
        deliver(&mut agent, &accepted(&subscribe), t0);
        deliver(
            &mut agent,
            &notify(&subscribe, 1, "text/plain", "hello"),
            t0,
        );
        deliver(
            &mut agent,
            &notify(&subscribe, 2, "application/conference-info+xml", ""),
            t0,
        );
        sent(&mut agent);
        let requests = notified(&mut agent);
        assert_eq!(requests.len(), 2);
        let mut conference = Conference::new();
        assert_eq!(
            conference.apply_notify(&requests[0]),
            Err(ConferenceInfoError::NotConferenceInfo)
        );
        assert_eq!(conference.apply_notify(&requests[1]), Ok(None));
        assert_eq!(conference.version(), None);
    }

    #[test]
    fn full_state_cannot_be_asked_for_on_a_subscription_that_does_not_exist() {
        let t0 = Instant::now();
        let (mut agent, _) = agent(t0);
        assert_eq!(
            agent.request_full_state(SubscriptionHandle(4_242), t0),
            Err(UaError::NoSuchSubscription)
        );
    }
}
