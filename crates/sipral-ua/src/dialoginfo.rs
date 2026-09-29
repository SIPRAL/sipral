// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! `application/dialog-info+xml`, and the table a busy lamp field is drawn
//! from (RFC 4235 §4).
//!
//! **This is not an XML parser and must not become one.** It reads the one
//! document RFC 4235 §4.4 defines and refuses everything else, because the
//! bytes arrive over UDP from whatever answered a SUBSCRIBE and there is no
//! version of "try harder" that is safe there. Every general-purpose XML
//! feature that has ever been a vulnerability is absent by construction rather
//! than by option: there is no document type declaration, so there are no
//! entity declarations, so there is no expansion to bound; there are no
//! external references, so nothing is fetched; and the nesting, the element
//! count, the attribute count and the length of every value are bounded before
//! the first byte is read. A document that needs any of it is refused whole.
//!
//! CDATA is refused for the same reason. §4.4's schema has no element whose
//! content is anything but a URI, a token or a number, so a document that
//! needs to escape markup is not one of these — and a construct that is never
//! needed is a construct that cannot be got wrong.
//!
//! **Namespaces are read as prefixes and otherwise ignored.** §4 puts these
//! documents in `urn:ietf:params:xml:ns:dialog-info`, and notifiers get the
//! binding wrong often enough that refusing on it would turn working phones
//! off. What identifies the body is the `Content-Type` that carried it; what
//! is matched here is the local name.
//!
//! **The table is §4.3's, and the version rule has one deliberate leniency.**
//! A document whose version is lower than what has already been applied is
//! discarded; one more than a step ahead means a notification was lost, and if
//! that one carried partial state the subscriber asks for full state again.
//! What §4.3 does not say is what to do with a version that repeats, and
//! repeating is what several PBXs do — every notification stamped `version=0`.
//! Discarding those freezes the lamp for ever, so a repeat is applied. It
//! cannot make the table wrong: full state replaces, and re-applying the same
//! partial update lands on the value it already holds.

use std::time::Duration;

/// The largest document that will be read at all.
///
/// Forty extensions with both parties named comes to a few kilobytes. This is
/// an order of magnitude above the largest real one and two below anything
/// that would matter for memory; what it is really for is putting a number on
/// the outermost loop.
const MAX_BYTES: usize = 64 * 1024;
/// How deep the elements may nest. §4.4's deepest path is `dialog-info` →
/// `dialog` → `local` → `target` → `param`, which is five.
const MAX_DEPTH: usize = 8;
/// How many elements will be read before the document is refused.
const MAX_NODES: usize = 8_192;
/// How many attributes one element may carry. §4.4's widest is `dialog`, with
/// five.
const MAX_ATTRIBUTES: usize = 24;
/// The longest attribute value or text run that will be kept.
const MAX_VALUE: usize = 1_024;
/// How many dialogs one document may report.
const MAX_DIALOGS: usize = 512;

/// Why a dialog information document could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DialogInfoError {
    /// The body is not XML, or the markup does not close.
    Malformed(&'static str),
    /// A construct this reader refuses on sight: a document type declaration,
    /// an entity declaration, a CDATA section, an entity reference that is not
    /// one of the five XML predefines or a character reference.
    Refused(&'static str),
    /// One of the bounds in this module was reached.
    TooLarge(&'static str),
    /// A value that has to be text is not UTF-8. §4 requires the document to
    /// be encoded in UTF-8.
    NotUtf8,
    /// The root element is not `dialog-info`.
    NotDialogInfo,
}

impl core::fmt::Display for DialogInfoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Malformed(what) => write!(f, "malformed dialog information: {what}"),
            Self::Refused(what) => write!(f, "refused: {what}"),
            Self::TooLarge(what) => write!(f, "too large: {what}"),
            Self::NotUtf8 => f.write_str("not UTF-8"),
            Self::NotDialogInfo => f.write_str("not a dialog-info document"),
        }
    }
}

impl core::error::Error for DialogInfoError {}

/// Where one dialog is, in the state machine of §3.7.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DialogPhase {
    /// The INVITE has gone and nothing has come back.
    Trying,
    /// A provisional response without a tag: there is not a dialog yet.
    Proceeding,
    /// A provisional response with a tag. The phone is ringing.
    Early,
    /// A 2xx. The call is up.
    Confirmed,
    /// Over.
    Terminated,
    /// A value §4.4's schema does not list. The element's content is
    /// `xs:string`, so a notifier may write one.
    Unknown,
}

impl DialogPhase {
    fn read(text: &[u8]) -> Self {
        if text.eq_ignore_ascii_case(b"trying") {
            Self::Trying
        } else if text.eq_ignore_ascii_case(b"proceeding") {
            Self::Proceeding
        } else if text.eq_ignore_ascii_case(b"early") {
            Self::Early
        } else if text.eq_ignore_ascii_case(b"confirmed") {
            Self::Confirmed
        } else if text.eq_ignore_ascii_case(b"terminated") {
            Self::Terminated
        } else {
            Self::Unknown
        }
    }

    /// How far along a lamp should read this as being.
    ///
    /// §3.7.2's virtual state machine, which is the rule for turning several
    /// dialogs into one indication: "If there is any dialog at the UA whose
    /// state is Confirmed, the virtual FSM is in the Confirmed state. If there
    /// are no dialogs at the UA in the Confirmed state but there is at least
    /// one in the Early state..." and so on down.
    const fn rank(self) -> u8 {
        match self {
            Self::Terminated | Self::Unknown => 0,
            Self::Trying => 1,
            Self::Proceeding => 2,
            Self::Early => 3,
            Self::Confirmed => 4,
        }
    }
}

/// What put a dialog into `terminated` (§4.1.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DialogEnded {
    /// A CANCEL, and then a 487.
    Cancelled,
    /// A non-2xx final response that was not a 487.
    Rejected,
    /// An invitation carrying a `Replaces` took it over (RFC 3891).
    Replaced,
    /// The observed user hung up.
    LocalBye,
    /// The other party did.
    RemoteBye,
    /// A request inside it earned a 481 or a 408.
    Error,
    /// A request inside it got no answer at all.
    Timeout,
}

impl DialogEnded {
    fn read(text: &[u8]) -> Option<Self> {
        Some(if text.eq_ignore_ascii_case(b"cancelled") {
            Self::Cancelled
        } else if text.eq_ignore_ascii_case(b"rejected") {
            Self::Rejected
        } else if text.eq_ignore_ascii_case(b"replaced") {
            Self::Replaced
        } else if text.eq_ignore_ascii_case(b"local-bye") {
            Self::LocalBye
        } else if text.eq_ignore_ascii_case(b"remote-bye") {
            Self::RemoteBye
        } else if text.eq_ignore_ascii_case(b"error") {
            Self::Error
        } else if text.eq_ignore_ascii_case(b"timeout") {
            Self::Timeout
        } else {
            return None;
        })
    }
}

/// Which end of the dialog the observed user is (§4.1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Initiated {
    /// The observed user placed the call.
    Locally,
    /// Somebody called them.
    Remotely,
}

/// One participant, as far as the notifier is willing to say (§4.1.6).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Participant {
    /// The `identity` element: the participant's address of record.
    pub identity: Option<Box<str>>,
    /// Its `display` attribute.
    pub display: Option<Box<str>>,
    /// The `uri` of the `target` element: where that end of the dialog is
    /// actually reachable.
    pub target: Option<Box<str>>,
}

/// One dialog, or one half of one (§4.1.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchedDialog {
    /// The `id` attribute, which is what rows of the table are keyed by. Not
    /// the RFC 3261 dialog identifier: §4.1.1 is explicit that it is "a
    /// different identifier than the dialog ID defined in RFC 3261, but
    /// related to it".
    pub id: Box<str>,
    /// The `Call-ID`, when the notifier says.
    pub call_id: Option<Box<str>>,
    /// The observed user's tag.
    pub local_tag: Option<Box<str>>,
    /// The other end's, absent while there is only a half-dialog.
    pub remote_tag: Option<Box<str>>,
    /// Which end the observed user is.
    pub direction: Option<Initiated>,
    /// Where the dialog is.
    pub phase: DialogPhase,
    /// What ended it, when it has ended and the notifier said.
    pub ended: Option<DialogEnded>,
    /// The status code of the response that caused the transition, when there
    /// was one.
    pub code: Option<u16>,
    /// How long since the state machine was created.
    pub duration: Option<Duration>,
    /// The observed user.
    pub local: Participant,
    /// Whoever they are talking to.
    pub remote: Participant,
}

impl WatchedDialog {
    fn new(id: Box<str>) -> Self {
        Self {
            id,
            call_id: None,
            local_tag: None,
            remote_tag: None,
            direction: None,
            phase: DialogPhase::Unknown,
            ended: None,
            code: None,
            duration: None,
            local: Participant::default(),
            remote: Participant::default(),
        }
    }
}

/// One `application/dialog-info+xml` document (§4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DialogInfo {
    /// The `version` attribute, which orders documents within a subscription.
    pub version: u32,
    /// Whether this is the whole picture or only what changed.
    pub full: bool,
    /// The `entity` attribute: whose dialogs these are.
    pub entity: Option<Box<str>>,
    /// The dialogs it reports.
    pub dialogs: Vec<WatchedDialog>,
}

/// What one document did to the table (§4.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Applied {
    /// It was merged in.
    Taken,
    /// Its version is behind what is already held, so it was discarded.
    Stale,
    /// It was merged, but a notification was lost on the way and this one
    /// carried only a change — so the picture may be missing something and
    /// §4.3 asks for a refresh to get full state back.
    Incomplete,
}

/// Everything one subscription has been told about, merged (§4.3).
#[derive(Clone, Debug, Default)]
pub struct DialogInfoTable {
    version: Option<u32>,
    rows: Vec<WatchedDialog>,
}

impl DialogInfoTable {
    /// The dialogs, in the order they were first heard of.
    #[must_use]
    pub fn dialogs(&self) -> &[WatchedDialog] {
        &self.rows
    }

    /// The last version applied, for a caller watching for gaps of its own.
    #[must_use]
    pub const fn version(&self) -> Option<u32> {
        self.version
    }

    /// What a lamp for this resource should show: §3.7.2's virtual state
    /// machine over every dialog in the table.
    ///
    /// `None` when nothing is going on, which is the state §4.1.2 leaves a
    /// row in once it has terminated.
    #[must_use]
    pub fn phase(&self) -> Option<DialogPhase> {
        self.rows
            .iter()
            .map(|row| row.phase)
            .max_by_key(|phase| phase.rank())
            .filter(|phase| phase.rank() > 0)
    }

    /// Merge one document in (§4.3).
    pub(crate) fn apply(&mut self, document: &DialogInfo) -> Applied {
        let gap = match self.version {
            // "If the value in the document is less than the local version,
            // the document is discarded without processing."
            Some(held) if document.version < held => return Applied::Stale,
            // "If the value in the document is more than one higher than the
            // local version number, the local version number is set to the
            // value in the new document and the document is processed."
            Some(held) => document.version > held.saturating_add(1),
            None => false,
        };
        self.version = Some(document.version);

        // "If it contains full state ... the contents of the table are flushed
        // and then repopulated from the document."
        if document.full {
            self.rows.clear();
        }
        for row in &document.dialogs {
            let room = self.rows.len() < MAX_DIALOGS;
            match self.rows.iter_mut().find(|held| held.id == row.id) {
                Some(held) => *held = row.clone(),
                None if room => self.rows.push(row.clone()),
                None => (),
            }
        }
        // "If a row is updated or created, such that its state is now
        // terminated, that entry MAY be removed from the table at any time."
        // It is removed here, because a lamp reads the table and a row that
        // has ended is a call that is over.
        self.rows.retain(|row| row.phase != DialogPhase::Terminated);

        if gap && !document.full {
            Applied::Incomplete
        } else {
            Applied::Taken
        }
    }
}

// -- reading the document ----------------------------------------------------

impl DialogInfo {
    /// Read one document.
    ///
    /// # Errors
    /// [`DialogInfoError`]. Every failure is the notifier's, and every one of
    /// them leaves the table the subscription already holds exactly as it was:
    /// a lamp showing what was last known is better than one showing what a
    /// malformed document happened to contain.
    pub fn parse(body: &[u8]) -> Result<Self, DialogInfoError> {
        if body.len() > MAX_BYTES {
            return Err(DialogInfoError::TooLarge("document"));
        }
        Builder::default().run(Reader::new(body))
    }
}

/// What the walk is putting values into.
#[derive(Default)]
struct Builder {
    document: Option<DialogInfo>,
    dialog: Option<WatchedDialog>,
    /// Which of `local` and `remote` is open, when one is.
    party: Option<bool>,
    /// Which element's text is being collected, when one wants it.
    text_into: Option<Wants>,
}

/// The three elements whose content, rather than attributes, carries the value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Wants {
    Phase,
    Duration,
    Identity,
}

impl Builder {
    fn run(mut self, mut reader: Reader<'_>) -> Result<DialogInfo, DialogInfoError> {
        let mut path: Vec<&[u8]> = Vec::new();
        for _ in 0..MAX_NODES {
            let Some(node) = reader.next()? else {
                let document = self.document.ok_or(DialogInfoError::NotDialogInfo)?;
                if !path.is_empty() {
                    return Err(DialogInfoError::Malformed("an element never closed"));
                }
                return Ok(document);
            };
            match node {
                Node::Open(element) => {
                    if path.len() >= MAX_DEPTH {
                        return Err(DialogInfoError::TooLarge("nesting"));
                    }
                    let name = local_name(element.name);
                    self.open(name, element.attributes, path.last().copied())?;
                    if element.empty {
                        self.close(name)?;
                    } else {
                        path.push(name);
                    }
                }
                Node::Close(name) => {
                    let name = local_name(name);
                    if path.pop() != Some(name) {
                        return Err(DialogInfoError::Malformed("closing tag does not match"));
                    }
                    self.close(name)?;
                }
                Node::Text(raw) => self.text(raw)?,
            }
        }
        Err(DialogInfoError::TooLarge("element count"))
    }

    fn open(
        &mut self,
        name: &[u8],
        attributes: Attributes<'_>,
        parent: Option<&[u8]>,
    ) -> Result<(), DialogInfoError> {
        self.text_into = None;
        match name {
            b"dialog-info" if self.document.is_none() => self.open_document(attributes)?,
            _ if self.document.is_none() => return Err(DialogInfoError::NotDialogInfo),
            b"dialog" => self.dialog = Some(open_dialog(attributes)?),
            b"local" | b"remote" => self.party = Some(name == b"local"),
            b"state" if parent == Some(b"dialog") => {
                self.read_state(attributes)?;
                self.text_into = Some(Wants::Phase);
            }
            b"duration" => self.text_into = Some(Wants::Duration),
            b"identity" if self.party.is_some() => {
                let display = attributes.text("display")?;
                if let Some(party) = self.party_mut() {
                    party.display = display;
                }
                self.text_into = Some(Wants::Identity);
            }
            b"target" if self.party.is_some() => {
                let uri = attributes.text("uri")?;
                if let Some(party) = self.party_mut() {
                    party.target = uri;
                }
            }
            _ => (),
        }
        Ok(())
    }

    fn open_document(&mut self, attributes: Attributes<'_>) -> Result<(), DialogInfoError> {
        let version = attributes
            .text("version")?
            .and_then(|text| text.parse::<u32>().ok())
            .unwrap_or(0);
        // §4.1: the attribute is "state", and its two values are "full" and
        // "partial". Absent, the document is read as full: it is the only
        // reading that cannot leave the table holding a row nothing will
        // ever correct
        let full = attributes
            .value("state")?
            .is_none_or(|value| !value.eq_ignore_ascii_case(b"partial"));
        self.document = Some(DialogInfo {
            version,
            full,
            entity: attributes.text("entity")?,
            dialogs: Vec::new(),
        });
        Ok(())
    }

    fn read_state(&mut self, attributes: Attributes<'_>) -> Result<(), DialogInfoError> {
        let ended = attributes
            .value("event")?
            .and_then(|value| DialogEnded::read(&value));
        let code = attributes
            .text("code")?
            .and_then(|text| text.parse::<u16>().ok())
            .filter(|code| (100..=699).contains(code));
        if let Some(dialog) = self.dialog.as_mut() {
            dialog.ended = ended;
            dialog.code = code;
        }
        Ok(())
    }

    fn close(&mut self, name: &[u8]) -> Result<(), DialogInfoError> {
        match name {
            b"dialog" => {
                if let (Some(document), Some(dialog)) = (self.document.as_mut(), self.dialog.take())
                {
                    if document.dialogs.len() >= MAX_DIALOGS {
                        return Err(DialogInfoError::TooLarge("dialog count"));
                    }
                    document.dialogs.push(dialog);
                }
            }
            b"local" | b"remote" => self.party = None,
            _ => (),
        }
        self.text_into = None;
        Ok(())
    }

    fn text(&mut self, raw: &[u8]) -> Result<(), DialogInfoError> {
        let Some(wants) = self.text_into else {
            return Ok(());
        };
        let text = unescape(raw)?;
        match wants {
            Wants::Phase => {
                if let Some(dialog) = self.dialog.as_mut() {
                    dialog.phase = DialogPhase::read(text.trim_ascii());
                }
            }
            Wants::Duration => {
                let seconds = as_str(text.trim_ascii())?.parse::<u64>().ok();
                if let (Some(dialog), Some(seconds)) = (self.dialog.as_mut(), seconds) {
                    dialog.duration = Some(Duration::from_secs(seconds));
                }
            }
            Wants::Identity => {
                let identity = Box::from(as_str(text.trim_ascii())?);
                if let Some(party) = self.party_mut() {
                    party.identity = Some(identity);
                }
            }
        }
        Ok(())
    }

    fn party_mut(&mut self) -> Option<&mut Participant> {
        let local = self.party?;
        let dialog = self.dialog.as_mut()?;
        Some(if local {
            &mut dialog.local
        } else {
            &mut dialog.remote
        })
    }
}

fn open_dialog(attributes: Attributes<'_>) -> Result<WatchedDialog, DialogInfoError> {
    // §4.1.1 makes `id` the only mandatory attribute, and §4.3 keys the table
    // by it. One without it names no row, and a synthesised name would make
    // every notification look like a new dialog
    let id = attributes
        .text("id")?
        .ok_or(DialogInfoError::Malformed("a dialog with no id"))?;
    let mut dialog = WatchedDialog::new(id);
    dialog.call_id = attributes.text("call-id")?;
    dialog.local_tag = attributes.text("local-tag")?;
    dialog.remote_tag = attributes.text("remote-tag")?;
    dialog.direction = match attributes.value("direction")? {
        Some(value) if value.eq_ignore_ascii_case(b"initiator") => Some(Initiated::Locally),
        Some(value) if value.eq_ignore_ascii_case(b"recipient") => Some(Initiated::Remotely),
        _ => None,
    };
    Ok(dialog)
}

/// A name with any namespace prefix taken off.
pub(crate) fn local_name(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|byte| *byte == b':') {
        Some(colon) => name.get(colon + 1..).unwrap_or(name),
        None => name,
    }
}

fn as_str(bytes: &[u8]) -> Result<&str, DialogInfoError> {
    core::str::from_utf8(bytes).map_err(|_| DialogInfoError::NotUtf8)
}

// -- the tokeniser -----------------------------------------------------------

/// One piece of markup.
pub(crate) enum Node<'a> {
    Open(Element<'a>),
    Close(&'a [u8]),
    Text(&'a [u8]),
}

pub(crate) struct Element<'a> {
    pub(crate) name: &'a [u8],
    pub(crate) attributes: Attributes<'a>,
    /// Written `<x/>`, so it closes itself.
    pub(crate) empty: bool,
}

/// The attributes of one element, read on demand.
#[derive(Clone, Copy)]
pub(crate) struct Attributes<'a> {
    raw: &'a [u8],
}

impl Attributes<'_> {
    /// One attribute's value, with references resolved.
    pub(crate) fn value(&self, name: &str) -> Result<Option<Vec<u8>>, DialogInfoError> {
        let mut rest = self.raw;
        for _ in 0..MAX_ATTRIBUTES {
            let Some(found) = next_attribute(rest)? else {
                return Ok(None);
            };
            rest = found.rest;
            if local_name(found.name).eq_ignore_ascii_case(name.as_bytes()) {
                return unescape(found.value).map(Some);
            }
        }
        Err(DialogInfoError::TooLarge("attribute count"))
    }

    /// The same, as text.
    pub(crate) fn text(&self, name: &str) -> Result<Option<Box<str>>, DialogInfoError> {
        match self.value(name)? {
            Some(value) => Ok(Some(Box::from(as_str(&value)?))),
            None => Ok(None),
        }
    }
}

/// One `name="value"` pair, and what follows it.
struct Attribute<'a> {
    name: &'a [u8],
    value: &'a [u8],
    rest: &'a [u8],
}

/// The next pair, or `None` when the tag has no more.
fn next_attribute(raw: &[u8]) -> Result<Option<Attribute<'_>>, DialogInfoError> {
    let rest = raw.trim_ascii_start();
    if rest.is_empty() {
        return Ok(None);
    }
    let equals = rest
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(DialogInfoError::Malformed("attribute without a value"))?;
    let name = rest.get(..equals).unwrap_or_default().trim_ascii();
    let after = rest
        .get(equals + 1..)
        .unwrap_or_default()
        .trim_ascii_start();
    // §2.3 of XML 1.0 allows either quote and requires one of them; an
    // unquoted value is not a document this reads
    let (&quote, body) = after
        .split_first()
        .filter(|(quote, _)| matches!(**quote, b'"' | b'\''))
        .ok_or(DialogInfoError::Malformed("attribute value is not quoted"))?;
    let end = body
        .iter()
        .position(|byte| *byte == quote)
        .ok_or(DialogInfoError::Malformed("attribute value never closes"))?;
    if end > MAX_VALUE {
        return Err(DialogInfoError::TooLarge("attribute value"));
    }
    Ok(Some(Attribute {
        name,
        value: body.get(..end).unwrap_or_default(),
        rest: body.get(end + 1..).unwrap_or_default(),
    }))
}

pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(body: &'a [u8]) -> Self {
        Self { rest: body }
    }

    /// The next node, or `None` at the end of the document.
    pub(crate) fn next(&mut self) -> Result<Option<Node<'a>>, DialogInfoError> {
        // at most one skipped construct per call is not enough: a document
        // starts with a declaration and may then carry comments
        for _ in 0..MAX_NODES {
            let rest = self.rest.trim_ascii_start();
            self.rest = rest;
            let Some(&first) = rest.first() else {
                return Ok(None);
            };
            if first != b'<' {
                return self.text().map(Some);
            }
            match rest.get(1) {
                Some(b'?') => self.skip(b"?>", "a processing instruction")?,
                Some(b'!') => {
                    if rest.starts_with(b"<!--") {
                        self.skip(b"-->", "a comment")?;
                    } else {
                        // <!DOCTYPE brings entity declarations, <![CDATA[
                        // brings content that is not markup, and neither is
                        // in a dialog-info document
                        return Err(DialogInfoError::Refused("a declaration or CDATA section"));
                    }
                }
                Some(b'/') => return self.close().map(Some),
                Some(_) => return self.open().map(Some),
                None => return Err(DialogInfoError::Malformed("a tag that never opens")),
            }
        }
        Err(DialogInfoError::TooLarge("element count"))
    }

    fn skip(&mut self, until: &[u8], what: &'static str) -> Result<(), DialogInfoError> {
        let at = find(self.rest, until).ok_or(DialogInfoError::Malformed(what))?;
        self.rest = self.rest.get(at + until.len()..).unwrap_or_default();
        Ok(())
    }

    fn text(&mut self) -> Result<Node<'a>, DialogInfoError> {
        let end = self
            .rest
            .iter()
            .position(|byte| *byte == b'<')
            .unwrap_or(self.rest.len());
        if end > MAX_VALUE {
            return Err(DialogInfoError::TooLarge("element content"));
        }
        let text = self.rest.get(..end).unwrap_or_default();
        self.rest = self.rest.get(end..).unwrap_or_default();
        Ok(Node::Text(text))
    }

    fn close(&mut self) -> Result<Node<'a>, DialogInfoError> {
        let end = tag_end(self.rest).ok_or(DialogInfoError::Malformed("a tag that never ends"))?;
        let name = self.rest.get(2..end).unwrap_or_default().trim_ascii();
        self.rest = self.rest.get(end + 1..).unwrap_or_default();
        Ok(Node::Close(name))
    }

    fn open(&mut self) -> Result<Node<'a>, DialogInfoError> {
        let end = tag_end(self.rest).ok_or(DialogInfoError::Malformed("a tag that never ends"))?;
        let inside = self.rest.get(1..end).unwrap_or_default();
        self.rest = self.rest.get(end + 1..).unwrap_or_default();
        let (inside, empty) = match inside.strip_suffix(b"/") {
            Some(head) => (head, true),
            None => (inside, false),
        };
        let split = inside
            .iter()
            .position(u8::is_ascii_whitespace)
            .unwrap_or(inside.len());
        let name = inside.get(..split).unwrap_or_default();
        if name.is_empty() {
            return Err(DialogInfoError::Malformed("a tag with no name"));
        }
        Ok(Node::Open(Element {
            name,
            attributes: Attributes {
                raw: inside.get(split..).unwrap_or_default(),
            },
            empty,
        }))
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The `>` that closes a tag, skipping the ones inside attribute values.
///
/// XML §2.4 forbids `<` and `&` in an attribute value and allows everything
/// else, `>` included — so `display="a &gt; b"` is the conventional spelling
/// and `display="a > b"` is legal too. Stopping at the first `>` would cut the
/// tag in half and read the rest of it as text.
fn tag_end(tag: &[u8]) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (at, byte) in tag.iter().enumerate() {
        if let Some(open) = quote {
            quote = (open != *byte).then_some(open);
        } else if matches!(*byte, b'"' | b'\'') {
            quote = Some(*byte);
        } else if *byte == b'>' {
            return Some(at);
        }
    }
    None
}

/// The five references XML predefines, and character references. Nothing else.
///
/// This is where a general-purpose reader would look a declaration up, and
/// where the billion laughs would expand. There is no table to look in: an
/// entity that is not one of these five is a document this refuses.
pub(crate) fn unescape(raw: &[u8]) -> Result<Vec<u8>, DialogInfoError> {
    if raw.len() > MAX_VALUE {
        return Err(DialogInfoError::TooLarge("value"));
    }
    if !raw.contains(&b'&') {
        return Ok(raw.to_vec());
    }
    let mut out = Vec::with_capacity(raw.len());
    let mut rest = raw;
    // one reference is at least three bytes, so the input's own length bounds
    // this as tightly as anything else would
    for _ in 0..=MAX_VALUE {
        let Some(at) = rest.iter().position(|byte| *byte == b'&') else {
            out.extend_from_slice(rest);
            return Ok(out);
        };
        out.extend_from_slice(rest.get(..at).unwrap_or_default());
        let after = rest.get(at + 1..).unwrap_or_default();
        let end = after
            .iter()
            .take(16)
            .position(|byte| *byte == b';')
            .ok_or(DialogInfoError::Malformed("a reference that never ends"))?;
        let name = after.get(..end).unwrap_or_default();
        push_reference(name, &mut out)?;
        rest = after.get(end + 1..).unwrap_or_default();
    }
    Err(DialogInfoError::TooLarge("references"))
}

fn push_reference(name: &[u8], out: &mut Vec<u8>) -> Result<(), DialogInfoError> {
    let byte = match name {
        b"amp" => b'&',
        b"lt" => b'<',
        b"gt" => b'>',
        b"quot" => b'"',
        b"apos" => b'\'',
        _ => return push_character(name, out),
    };
    out.push(byte);
    Ok(())
}

fn push_character(name: &[u8], out: &mut Vec<u8>) -> Result<(), DialogInfoError> {
    let Some(digits) = name.strip_prefix(b"#") else {
        return Err(DialogInfoError::Refused("an entity reference"));
    };
    let (digits, radix) = match digits.strip_prefix(b"x").or(digits.strip_prefix(b"X")) {
        Some(hex) => (hex, 16),
        None => (digits, 10),
    };
    let text = as_str(digits)?;
    let point = u32::from_str_radix(text, radix)
        .ok()
        .and_then(char::from_u32)
        .ok_or(DialogInfoError::Refused("a character reference"))?;
    let mut buffer = [0_u8; 4];
    out.extend_from_slice(point.encode_utf8(&mut buffer).as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Applied, DialogEnded, DialogInfo, DialogInfoError, DialogInfoTable, DialogPhase, Initiated,
        MAX_DEPTH, MAX_VALUE,
    };
    use std::time::Duration;

    /// §4.2's sample notification body, verbatim.
    const SAMPLE: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:dialog-info"
  version="1" state="full">
  <dialog id="123456">
     <state>confirmed</state>
     <duration>274</duration>
     <local>
       <identity display="Alice">sip:alice@example.com</identity>
       <target uri="sip:alice@pc33.example.com">
         <param pname="isfocus" pval="true"/>
         <param pname="class" pval="personal"/>
       </target>
     </local>
     <remote>
       <identity display="Bob">sip:bob@example.org</identity>
       <target uri="sip:bobster@phone21.example.org"/>
     </remote>
  </dialog>
</dialog-info>"#;

    fn parse(body: &[u8]) -> DialogInfo {
        DialogInfo::parse(body).expect("a document")
    }

    #[test]
    fn the_rfcs_own_sample_reads_as_the_rfc_describes_it() {
        let document = parse(SAMPLE);
        assert_eq!(document.version, 1);
        assert!(document.full);
        assert_eq!(document.dialogs.len(), 1);
        let dialog = document.dialogs.first().expect("one dialog");
        assert_eq!(&*dialog.id, "123456");
        assert_eq!(dialog.phase, DialogPhase::Confirmed);
        assert_eq!(dialog.duration, Some(Duration::from_secs(274)));
        assert_eq!(dialog.local.display.as_deref(), Some("Alice"));
        assert_eq!(
            dialog.local.identity.as_deref(),
            Some("sip:alice@example.com")
        );
        assert_eq!(
            dialog.local.target.as_deref(),
            Some("sip:alice@pc33.example.com")
        );
        assert_eq!(dialog.remote.display.as_deref(), Some("Bob"));
        assert_eq!(
            dialog.remote.target.as_deref(),
            Some("sip:bobster@phone21.example.org")
        );
    }

    #[test]
    fn the_identifiers_and_the_direction_are_read_when_they_are_there() {
        // 4.1.1's own example
        let document = parse(
            br#"<?xml version="1.0"?>
            <dialog-info xmlns="urn:ietf:params:xml:ns:dialog-info"
                         version="0" state="partial"
                         entity="sip:alice@example.com">
              <dialog id="as7d900as8" call-id="a84b4c76e66710"
                      local-tag="1928301774" direction="initiator">
                <state>early</state>
              </dialog>
            </dialog-info>"#,
        );
        assert!(!document.full);
        assert_eq!(document.entity.as_deref(), Some("sip:alice@example.com"));
        let dialog = document.dialogs.first().expect("one dialog");
        assert_eq!(dialog.call_id.as_deref(), Some("a84b4c76e66710"));
        assert_eq!(dialog.local_tag.as_deref(), Some("1928301774"));
        assert_eq!(dialog.remote_tag, None, "a half-dialog names no remote tag");
        assert_eq!(dialog.direction, Some(Initiated::Locally));
        assert_eq!(dialog.phase, DialogPhase::Early);
    }

    #[test]
    fn a_terminated_dialog_says_what_ended_it() {
        // 4.1.2: <state event="rejected" code="486">terminated</state>
        let document = parse(
            br#"<dialog-info version="3" state="full"><dialog id="x">
                <state event="rejected" code="486">terminated</state>
                </dialog></dialog-info>"#,
        );
        let dialog = document.dialogs.first().expect("one dialog");
        assert_eq!(dialog.phase, DialogPhase::Terminated);
        assert_eq!(dialog.ended, Some(DialogEnded::Rejected));
        assert_eq!(dialog.code, Some(486));
    }

    #[test]
    fn the_five_predefined_references_are_resolved_and_nothing_else_is() {
        let document = parse(
            br#"<dialog-info version="0" state="full"><dialog id="a&amp;b">
                <state>confirmed</state>
                <local><identity display="Alice &quot;A&quot; &#65;">
                sip:a@b</identity></local>
                </dialog></dialog-info>"#,
        );
        let dialog = document.dialogs.first().expect("one dialog");
        assert_eq!(&*dialog.id, "a&b");
        assert_eq!(dialog.local.display.as_deref(), Some(r#"Alice "A" A"#));

        assert_eq!(
            DialogInfo::parse(
                br#"<dialog-info version="0"><dialog id="&lol1;"><state>confirmed</state></dialog></dialog-info>"#
            ),
            Err(DialogInfoError::Refused("an entity reference")),
            "there is no table to look an entity up in, and that is the point"
        );
    }

    #[test]
    fn a_document_type_declaration_is_refused_before_it_can_declare_anything() {
        // the billion laughs starts here, and never gets any further
        let hostile = br#"<?xml version="1.0"?>
            <!DOCTYPE dialog-info [
              <!ENTITY lol "lol">
              <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
            ]>
            <dialog-info version="0" state="full"><dialog id="&lol1;">
            <state>confirmed</state></dialog></dialog-info>"#;
        assert_eq!(
            DialogInfo::parse(hostile),
            Err(DialogInfoError::Refused("a declaration or CDATA section"))
        );
    }

    #[test]
    fn nesting_is_bounded_and_the_bound_is_reached_before_the_stack_is() {
        let mut body = b"<dialog-info version=\"0\">".to_vec();
        for _ in 0..64 {
            body.extend_from_slice(b"<a>");
        }
        assert_eq!(
            DialogInfo::parse(&body),
            Err(DialogInfoError::TooLarge("nesting")),
            "{MAX_DEPTH} deep is as far as a dialog-info document ever goes"
        );
    }

    #[test]
    fn an_unbounded_attribute_is_refused_rather_than_kept() {
        let mut body = b"<dialog-info version=\"0\" entity=\"".to_vec();
        body.extend(std::iter::repeat_n(b'x', MAX_VALUE + 1));
        body.extend_from_slice(b"\"/>");
        assert_eq!(
            DialogInfo::parse(&body),
            Err(DialogInfoError::TooLarge("attribute value"))
        );
    }

    #[test]
    fn a_body_that_is_not_xml_at_all_is_refused_and_says_so() {
        for body in [
            &b""[..],
            &b"not xml"[..],
            &b"{\"state\":\"confirmed\"}"[..],
            &b"<dialog-info"[..],
            &b"<dialog-info>"[..],
            &b"<dialog-info></dialog-info"[..],
            &b"<dialog-info><dialog id=x></dialog></dialog-info>"[..],
            &b"<dialog-info><dialog><state>confirmed</state></dialog></dialog-info>"[..],
            &b"<dialog-info><dialog id=\"a\"></wrong></dialog-info>"[..],
            &b"<presence><tuple/></presence>"[..],
            // valid UTF-16, and 4 requires UTF-8
            &b"<dialog-info version=\"0\" entity=\"\xff\xfe\xff\"/>"[..],
        ] {
            assert!(
                DialogInfo::parse(body).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    #[test]
    fn an_angle_bracket_inside_an_attribute_does_not_end_the_tag() {
        // XML 2.4 forbids "<" and "&" in an attribute value and allows the
        // rest, so this is a legal document
        let document = parse(
            br#"<dialog-info version="0" state="full"><dialog id="a">
                <state>confirmed</state>
                <local><identity display="Alice > Bob">sip:a@b</identity></local>
                </dialog></dialog-info>"#,
        );
        let dialog = document.dialogs.first().expect("one dialog");
        assert_eq!(dialog.local.display.as_deref(), Some("Alice > Bob"));
        assert_eq!(dialog.local.identity.as_deref(), Some("sip:a@b"));
        assert_eq!(dialog.phase, DialogPhase::Confirmed);
    }

    #[test]
    fn an_element_that_never_closes_is_not_a_document() {
        assert_eq!(
            DialogInfo::parse(b"<dialog-info version=\"0\"><dialog id=\"a\">"),
            Err(DialogInfoError::Malformed("an element never closed"))
        );
    }

    #[test]
    fn the_table_keeps_the_last_version_and_discards_what_is_behind_it() {
        // 4.3: "If the value in the document is less than the local version,
        // the document is discarded without processing."
        let mut table = DialogInfoTable::default();
        assert_eq!(table.apply(&parse(SAMPLE)), Applied::Taken);
        assert_eq!(table.version(), Some(1));
        assert_eq!(table.phase(), Some(DialogPhase::Confirmed));

        let older = parse(br#"<dialog-info version="0" state="full"></dialog-info>"#);
        assert_eq!(table.apply(&older), Applied::Stale);
        assert_eq!(table.dialogs().len(), 1, "the older document did nothing");
    }

    #[test]
    fn full_state_replaces_the_table_and_partial_state_updates_it() {
        let mut table = DialogInfoTable::default();
        table.apply(&parse(SAMPLE));

        let partial = parse(
            br#"<dialog-info version="2" state="partial"><dialog id="789">
                <state>early</state></dialog></dialog-info>"#,
        );
        assert_eq!(table.apply(&partial), Applied::Taken);
        assert_eq!(table.dialogs().len(), 2, "the first dialog is still there");

        let full = parse(
            br#"<dialog-info version="3" state="full"><dialog id="789">
                <state>confirmed</state></dialog></dialog-info>"#,
        );
        assert_eq!(table.apply(&full), Applied::Taken);
        assert_eq!(table.dialogs().len(), 1, "full state flushes what was held");
    }

    #[test]
    fn a_terminated_dialog_leaves_the_table_and_the_lamp_goes_out() {
        let mut table = DialogInfoTable::default();
        table.apply(&parse(SAMPLE));
        let over = parse(
            br#"<dialog-info version="2" state="partial"><dialog id="123456">
                <state event="remote-bye">terminated</state></dialog></dialog-info>"#,
        );
        table.apply(&over);
        assert!(table.dialogs().is_empty());
        assert_eq!(table.phase(), None);
    }

    #[test]
    fn a_gap_in_a_partial_document_asks_for_full_state_back() {
        // 4.3: "If the document did not contain full state, the subscriber
        // SHOULD generate a refresh request (SUBSCRIBE) to trigger a full
        // state notification."
        let mut table = DialogInfoTable::default();
        table.apply(&parse(SAMPLE));
        let jumped = parse(
            br#"<dialog-info version="9" state="partial"><dialog id="789">
                <state>early</state></dialog></dialog-info>"#,
        );
        assert_eq!(table.apply(&jumped), Applied::Incomplete);
        assert_eq!(table.version(), Some(9), "and the gap is not chased twice");

        let full = parse(
            br#"<dialog-info version="20" state="full"><dialog id="789">
                <state>early</state></dialog></dialog-info>"#,
        );
        assert_eq!(
            table.apply(&full),
            Applied::Taken,
            "a gap that carried full state is not a gap in the picture"
        );
    }

    #[test]
    fn a_version_that_never_moves_still_updates_the_lamp() {
        // several PBXs stamp every notification version=0; discarding those
        // freezes the lamp for as long as the subscription lasts
        let mut table = DialogInfoTable::default();
        for phase in ["early", "confirmed"] {
            let body = format!(
                r#"<dialog-info version="0" state="full"><dialog id="a">
                <state>{phase}</state></dialog></dialog-info>"#
            );
            assert_eq!(table.apply(&parse(body.as_bytes())), Applied::Taken);
        }
        assert_eq!(table.phase(), Some(DialogPhase::Confirmed));
    }

    #[test]
    fn the_lamp_reads_the_most_advanced_dialog_of_several() {
        // 3.7.2: "If there is any dialog at the UA whose state is Confirmed,
        // the virtual FSM is in the Confirmed state"
        let mut table = DialogInfoTable::default();
        table.apply(&parse(
            br#"<dialog-info version="0" state="full">
                <dialog id="a"><state>trying</state></dialog>
                <dialog id="b"><state>confirmed</state></dialog>
                <dialog id="c"><state>early</state></dialog>
                </dialog-info>"#,
        ));
        assert_eq!(table.phase(), Some(DialogPhase::Confirmed));
    }
}
