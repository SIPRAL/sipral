// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! `application/pidf+xml` (RFC 3863), with the activities of rich presence
//! (RFC 4480) that phones actually show.
//!
//! A presence document names a presentity (`entity`) and reports it as a set
//! of tuples, each with a `basic` status of `open` or `closed`, an optional
//! contact address, notes and a timestamp (§4.1). RPID adds what the person
//! behind it is doing, in a `person` element of the data model (RFC 4479)
//! whose `activities` list tokens such as `away` or `on-the-phone`.
//!
//! **Reading is [`crate::DialogInfo`]'s reader, with every refusal it has.**
//! A presence document arrives in a NOTIFY from whatever answered a
//! SUBSCRIBE, or in a PUBLISH from whatever sent one, so it is held to the
//! same bounds: no declarations, no entities beyond the predefined ones, no
//! CDATA, and bounded size, nesting and counts. Namespaces are read as
//! prefixes and ignored; what is matched is the local name and where it
//! sits, so an RPID `note` inside `activities` is never mistaken for a PIDF
//! `note`.
//!
//! **Writing escapes everything it did not choose.** Every value that goes
//! into a document is escaped, the identifiers the schema makes `xs:ID` and
//! the names of unlisted activities are checked against the XML name rules
//! before anything is written, and a document that cannot be written
//! correctly is refused rather than written approximately.
//!
//! Mood and the other RPID elements are not modelled: an
//! element this module does not read is skipped, not refused.

use core::fmt::Write as _;

use crate::conference::{TreeLimits, XmlNode, read_tree};
use crate::dialoginfo::DialogInfoError;

/// The body type (RFC 3863).
pub const PIDF_TYPE: &str = "application/pidf+xml";

const PIDF_NS: &str = "urn:ietf:params:xml:ns:pidf";
const DATA_MODEL_NS: &str = "urn:ietf:params:xml:ns:pidf:data-model";
const RPID_NS: &str = "urn:ietf:params:xml:ns:pidf:rpid";

/// The largest document read at all.
const MAX_BYTES: usize = 64 * 1024;
/// How deep elements may nest: `presence` → `tuple` → `status` → `basic`
/// is four, `presence` → `person` → `activities` → an activity is four.
const MAX_DEPTH: usize = 8;
/// How many nodes are read before the document is refused.
const MAX_NODES: usize = 4_096;
/// The longest text one element may hold.
const MAX_TEXT: usize = 1_024;
/// How many tuples one document may carry.
const MAX_TUPLES: usize = 64;
/// How many notes one element may carry.
const MAX_NOTES: usize = 16;
/// How many activities one person may carry.
const MAX_ACTIVITIES: usize = 16;

/// Why a presence document could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PresenceError {
    /// The body is not XML, the markup does not close, or a mandatory part
    /// is missing.
    Malformed(&'static str),
    /// A construct the reader refuses on sight (see [`crate::DialogInfoError`]).
    Refused(&'static str),
    /// One of the bounds in this module was reached.
    TooLarge(&'static str),
    /// A value that has to be text is not UTF-8.
    NotUtf8,
    /// The root element is not `presence`.
    NotPresence,
    /// A value cannot be written into a document as it stands.
    Unwritable(&'static str),
}

impl core::fmt::Display for PresenceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Malformed(what) => write!(f, "malformed presence document: {what}"),
            Self::Refused(what) => write!(f, "refused: {what}"),
            Self::TooLarge(what) => write!(f, "too large: {what}"),
            Self::NotUtf8 => f.write_str("not UTF-8"),
            Self::NotPresence => f.write_str("not a presence document"),
            Self::Unwritable(what) => write!(f, "cannot be written: {what}"),
        }
    }
}

impl core::error::Error for PresenceError {}

impl From<DialogInfoError> for PresenceError {
    fn from(error: DialogInfoError) -> Self {
        match error {
            DialogInfoError::Malformed(what) => Self::Malformed(what),
            DialogInfoError::Refused(what) => Self::Refused(what),
            DialogInfoError::TooLarge(what) => Self::TooLarge(what),
            DialogInfoError::NotUtf8 => Self::NotUtf8,
            DialogInfoError::NotDialogInfo => Self::NotPresence,
        }
    }
}

/// A tuple's `basic` status (§4.1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Basic {
    /// Reachable through this tuple.
    Open,
    /// Not reachable through it.
    Closed,
}

impl Basic {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

/// A `note`, with its `xml:lang` when it has one (§4.1.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Note {
    /// The text.
    pub text: Box<str>,
    /// The language tag.
    pub lang: Option<Box<str>>,
}

impl Note {
    /// A note with no language tag.
    #[must_use]
    pub fn new(text: &str) -> Self {
        Self {
            text: Box::from(text),
            lang: None,
        }
    }
}

/// A tuple's `contact` (§4.1.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Contact {
    /// The URI.
    pub uri: Box<str>,
    /// The `priority` attribute in thousandths, 0 to 1000: RFC 3261's
    /// qvalue, which is what the schema restricts it to.
    pub priority: Option<u16>,
}

/// One `tuple` (§4.1.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tuple {
    /// The `id` attribute: an `xs:ID`, unique within the document.
    pub id: Box<str>,
    /// `status/basic`.
    pub basic: Option<Basic>,
    /// `contact`.
    pub contact: Option<Contact>,
    /// Every `note`.
    pub notes: Vec<Note>,
    /// `timestamp`, as written: an `xs:dateTime`.
    pub timestamp: Option<Box<str>>,
}

impl Tuple {
    /// A tuple with a basic status and nothing else.
    #[must_use]
    pub fn new(id: &str, basic: Basic) -> Self {
        Self {
            id: Box::from(id),
            basic: Some(basic),
            contact: None,
            notes: Vec::new(),
            timestamp: None,
        }
    }
}

/// What the person is doing (RFC 4480 `activities`), for the activities phones
/// show; the rest are kept by name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Activity {
    /// `away`.
    Away,
    /// `busy`.
    Busy,
    /// `on-the-phone`.
    OnThePhone,
    /// `meeting`.
    Meeting,
    /// `vacation`.
    Vacation,
    /// Another activity element RFC 4480 lists (`meal`, `travel`,
    /// `unknown`...), by its local name.
    Unlisted(Box<str>),
    /// `other`: an activity described in free text.
    Other(Box<str>),
}

impl Activity {
    const LISTED: [(&'static str, Self); 5] = [
        ("away", Self::Away),
        ("busy", Self::Busy),
        ("on-the-phone", Self::OnThePhone),
        ("meeting", Self::Meeting),
        ("vacation", Self::Vacation),
    ];

    fn read(node: &XmlNode<'_>) -> Result<Self, DialogInfoError> {
        if node.name == b"other" {
            return Ok(Self::Other(Box::from(node.trimmed()?)));
        }
        for (name, activity) in Self::LISTED {
            if node.name == name.as_bytes() {
                return Ok(activity);
            }
        }
        Ok(Self::Unlisted(Box::from(crate::dialoginfo::as_str(
            node.name,
        )?)))
    }
}

/// The data model's `person` element (RFC 4479), as RPID uses it: the human behind
/// the tuples.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Person {
    /// The `id` attribute, an `xs:ID`.
    pub id: Box<str>,
    /// Its activities.
    pub activities: Vec<Activity>,
}

/// One `application/pidf+xml` document (§4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presence {
    /// The `entity` attribute: the presentity's URI (`pres:`, `sip:`...).
    pub entity: Box<str>,
    /// Every `tuple`, in order.
    pub tuples: Vec<Tuple>,
    /// The notes directly under `presence`.
    pub notes: Vec<Note>,
    /// The RPID person, when the document carries one.
    pub person: Option<Person>,
}

impl Presence {
    /// A document about `entity` with nothing in it yet.
    #[must_use]
    pub fn new(entity: &str) -> Self {
        Self {
            entity: Box::from(entity),
            tuples: Vec::new(),
            notes: Vec::new(),
            person: None,
        }
    }

    /// Read one document.
    ///
    /// # Errors
    /// [`PresenceError`], never [`PresenceError::Unwritable`].
    pub fn parse(body: &[u8]) -> Result<Self, PresenceError> {
        let root = read_tree(
            body,
            TreeLimits {
                bytes: MAX_BYTES,
                depth: MAX_DEPTH,
                nodes: MAX_NODES,
                text: MAX_TEXT,
            },
        )?;
        if root.name != b"presence" {
            return Err(PresenceError::NotPresence);
        }
        // §4.1.1: the one attribute `presence` must carry
        let entity = root
            .attributes
            .text("entity")?
            .ok_or(PresenceError::Malformed("no entity"))?;
        let mut tuples = Vec::new();
        for node in root.children_named("tuple") {
            if tuples.len() >= MAX_TUPLES {
                return Err(PresenceError::TooLarge("tuples"));
            }
            tuples.push(read_tuple(node)?);
        }
        Ok(Self {
            entity,
            tuples,
            notes: read_notes(&root)?,
            person: root.child("person").map(read_person).transpose()?,
        })
    }

    /// Whether any tuple is `open`: the one bit a buddy list shows.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.tuples
            .iter()
            .any(|tuple| tuple.basic == Some(Basic::Open))
    }

    /// The person's activities, or nothing when there is no person.
    #[must_use]
    pub fn activities(&self) -> &[Activity] {
        self.person
            .as_ref()
            .map_or(&[], |person| person.activities.as_slice())
    }

    /// Write the document, UTF-8, with the XML declaration §4.1 shows.
    ///
    /// The RPID and data-model namespaces are declared only when there is a
    /// person to write.
    ///
    /// # Errors
    /// [`PresenceError::Unwritable`]: an empty entity, an identifier that is
    /// not an XML name, two tuples with one identifier, a priority above
    /// 1000, or an unlisted activity whose name is not an XML name.
    pub fn to_xml(&self) -> Result<Vec<u8>, PresenceError> {
        if self.entity.is_empty() {
            return Err(PresenceError::Unwritable("an empty entity"));
        }
        let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        out.push_str("<presence xmlns=\"");
        out.push_str(PIDF_NS);
        out.push('"');
        if self.person.is_some() {
            push_raw(&mut out, " xmlns:dm=\"", DATA_MODEL_NS, "\"");
            push_raw(&mut out, " xmlns:rpid=\"", RPID_NS, "\"");
        }
        out.push_str(" entity=\"");
        escape(&mut out, &self.entity);
        out.push_str("\">\n");
        let mut ids: Vec<&str> = Vec::new();
        for tuple in &self.tuples {
            checked_id(&tuple.id, &ids)?;
            ids.push(&tuple.id);
            write_tuple(&mut out, tuple)?;
        }
        write_notes(&mut out, &self.notes, " ");
        if let Some(ref person) = self.person {
            checked_id(&person.id, &ids)?;
            write_person(&mut out, person)?;
        }
        out.push_str("</presence>\n");
        Ok(out.into_bytes())
    }
}

// -- reading -----------------------------------------------------------------

fn read_notes(node: &XmlNode<'_>) -> Result<Vec<Note>, DialogInfoError> {
    let mut notes = Vec::new();
    for note in node.children_named("note") {
        if notes.len() >= MAX_NOTES {
            return Err(DialogInfoError::TooLarge("notes"));
        }
        notes.push(Note {
            text: Box::from(note.trimmed()?),
            lang: note.attributes.text("lang")?,
        });
    }
    Ok(notes)
}

fn read_tuple(node: &XmlNode<'_>) -> Result<Tuple, PresenceError> {
    // §4.1.2: `id` is mandatory; it is what tells one tuple from another
    let id = node
        .attributes
        .text("id")?
        .ok_or(PresenceError::Malformed("a tuple with no id"))?;
    // §4.1.3: every tuple has a status, even one with nothing in it
    let status = node
        .child("status")
        .ok_or(PresenceError::Malformed("a tuple with no status"))?;
    let basic = match status.child("basic") {
        Some(basic) => match basic.trimmed()? {
            "open" => Some(Basic::Open),
            "closed" => Some(Basic::Closed),
            _ => return Err(PresenceError::Malformed("basic is neither open nor closed")),
        },
        None => None,
    };
    let contact = match node.child("contact") {
        Some(contact) => Some(Contact {
            uri: Box::from(contact.trimmed()?),
            priority: contact
                .attributes
                .text("priority")?
                .map(|text| qvalue(&text))
                .transpose()?,
        }),
        None => None,
    };
    Ok(Tuple {
        id,
        basic,
        contact,
        notes: read_notes(node)?,
        timestamp: node.child_text("timestamp")?,
    })
}

fn read_person(node: &XmlNode<'_>) -> Result<Person, PresenceError> {
    let id = node
        .attributes
        .text("id")?
        .ok_or(PresenceError::Malformed("a person with no id"))?;
    let mut activities = Vec::new();
    if let Some(list) = node.child("activities") {
        // RFC 4480: the list may carry notes of its own, which are not
        // activities
        for child in list.children.iter().filter(|child| child.name != b"note") {
            if activities.len() >= MAX_ACTIVITIES {
                return Err(PresenceError::TooLarge("activities"));
            }
            activities.push(Activity::read(child)?);
        }
    }
    Ok(Person { id, activities })
}

/// RFC 3261 §25.1's qvalue: `"0" [ "." 0*3DIGIT ]` or `"1" [ "." 0*3("0") ]`,
/// as thousandths.
fn qvalue(text: &str) -> Result<u16, PresenceError> {
    const BAD: PresenceError = PresenceError::Malformed("priority is not a qvalue");
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(BAD);
    }
    let mut thousandths: u16 = 0;
    for (at, byte) in fraction.bytes().enumerate() {
        let scale: u16 = match at {
            0 => 100,
            1 => 10,
            _ => 1,
        };
        thousandths += u16::from(byte - b'0') * scale;
    }
    match whole {
        "0" => Ok(thousandths),
        "1" if thousandths == 0 => Ok(1_000),
        _ => Err(BAD),
    }
}

// -- writing -----------------------------------------------------------------

/// Text or an attribute value, escaped for either place.
fn escape(out: &mut String, text: &str) {
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
}

fn push_raw(out: &mut String, before: &str, value: &str, after: &str) {
    out.push_str(before);
    out.push_str(value);
    out.push_str(after);
}

/// An XML name without a colon (XML Namespaces' `NCName`), in the ASCII
/// subset: a letter or `_`, then letters, digits, `-`, `_` and `.`.
fn is_ncname(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// An `xs:ID`: a name, and not one already used in this document.
fn checked_id(id: &str, used: &[&str]) -> Result<(), PresenceError> {
    if !is_ncname(id) {
        return Err(PresenceError::Unwritable("an id that is not an XML name"));
    }
    if used.contains(&id) {
        return Err(PresenceError::Unwritable("an id used twice"));
    }
    Ok(())
}

fn write_notes(out: &mut String, notes: &[Note], indent: &str) {
    for note in notes {
        out.push_str(indent);
        out.push_str("<note");
        if let Some(ref lang) = note.lang {
            out.push_str(" xml:lang=\"");
            escape(out, lang);
            out.push('"');
        }
        out.push('>');
        escape(out, &note.text);
        out.push_str("</note>\n");
    }
}

fn write_tuple(out: &mut String, tuple: &Tuple) -> Result<(), PresenceError> {
    out.push_str(" <tuple id=\"");
    escape(out, &tuple.id);
    out.push_str("\">\n  <status>");
    if let Some(basic) = tuple.basic {
        push_raw(out, "<basic>", basic.as_str(), "</basic>");
    }
    out.push_str("</status>\n");
    if let Some(ref contact) = tuple.contact {
        out.push_str("  <contact");
        if let Some(priority) = contact.priority {
            if priority > 1_000 {
                return Err(PresenceError::Unwritable("a priority above 1"));
            }
            let _ = write!(out, " priority=\"{}\"", format_qvalue(priority));
        }
        out.push('>');
        escape(out, &contact.uri);
        out.push_str("</contact>\n");
    }
    write_notes(out, &tuple.notes, "  ");
    if let Some(ref timestamp) = tuple.timestamp {
        out.push_str("  <timestamp>");
        escape(out, timestamp);
        out.push_str("</timestamp>\n");
    }
    out.push_str(" </tuple>\n");
    Ok(())
}

/// Thousandths as the shortest qvalue that says them.
fn format_qvalue(thousandths: u16) -> String {
    if thousandths >= 1_000 {
        return String::from("1");
    }
    let digits = format!("{thousandths:03}");
    let digits = digits.trim_end_matches('0');
    if digits.is_empty() {
        String::from("0")
    } else {
        format!("0.{digits}")
    }
}

fn write_person(out: &mut String, person: &Person) -> Result<(), PresenceError> {
    out.push_str(" <dm:person id=\"");
    escape(out, &person.id);
    out.push_str("\">\n");
    if !person.activities.is_empty() {
        out.push_str("  <rpid:activities>");
        for activity in &person.activities {
            match *activity {
                Activity::Other(ref text) => {
                    out.push_str("<rpid:other>");
                    escape(out, text);
                    out.push_str("</rpid:other>");
                }
                Activity::Unlisted(ref name) => {
                    if !is_ncname(name) || &**name == "other" {
                        return Err(PresenceError::Unwritable(
                            "an activity name that is not an XML name",
                        ));
                    }
                    push_raw(out, "<rpid:", name, "/>");
                }
                ref listed => {
                    let name = Activity::LISTED
                        .iter()
                        .find(|(_, activity)| activity == listed)
                        .map_or("unknown", |(name, _)| name);
                    push_raw(out, "<rpid:", name, "/>");
                }
            }
        }
        out.push_str("</rpid:activities>\n");
    }
    out.push_str(" </dm:person>\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        Activity, Basic, Contact, MAX_TUPLES, Note, Person, Presence, PresenceError, Tuple,
        format_qvalue, qvalue,
    };

    /// RFC 3863 §6's example: two tuples, one with an extension inside its
    /// status, notes in two languages and a timestamp, and a note on the
    /// document itself. The carrier's domain is moved under `example.net`,
    /// the only change.
    const RFC3863: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf"
    xmlns:im="urn:ietf:params:xml:ns:pidf:im"
    xmlns:myex="http://id.example.com/presence/"
    entity="pres:someone@example.com">
  <tuple id="bs35r9">
    <status>
      <basic>open</basic>
      <im:im>busy</im:im>
      <myex:location>home</myex:location>
    </status>
    <contact priority="0.8">im:someone@mobilecarrier.example.net</contact>
    <note xml:lang="en">Don't Disturb Please!</note>
    <note xml:lang="fr">Ne derangez pas, s'il vous plait</note>
    <timestamp>2001-10-27T16:49:29Z</timestamp>
  </tuple>
  <tuple id="eg92n8">
    <status>
      <basic>open</basic>
    </status>
    <contact priority="1.0">mailto:someone@example.com</contact>
  </tuple>
  <note>I'll be in Tokyo next week</note>
</presence>"#;

    /// A person with activities in the shape RFC 4480 gives them,
    /// including the note the activities list may carry.
    const RPID: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<presence xmlns="urn:ietf:params:xml:ns:pidf"
    xmlns:dm="urn:ietf:params:xml:ns:pidf:data-model"
    xmlns:rpid="urn:ietf:params:xml:ns:pidf:rpid"
    entity="pres:someone@example.com">
  <tuple id="bs35r9">
    <status><basic>open</basic></status>
  </tuple>
  <dm:person id="p1">
    <rpid:activities from="2005-05-30T12:00:00+05:00"
        until="2005-05-30T17:00:00+05:00">
      <rpid:note>Far away</rpid:note>
      <rpid:away/>
    </rpid:activities>
  </dm:person>
</presence>"#;

    #[test]
    fn the_rfcs_own_example_reads_as_the_rfc_describes_it() {
        let presence = Presence::parse(RFC3863.as_bytes()).expect("a document");
        assert_eq!(&*presence.entity, "pres:someone@example.com");
        assert_eq!(presence.tuples.len(), 2);
        let first = &presence.tuples[0];
        assert_eq!(&*first.id, "bs35r9");
        assert_eq!(first.basic, Some(Basic::Open));
        let contact = first.contact.as_ref().expect("a contact");
        assert_eq!(&*contact.uri, "im:someone@mobilecarrier.example.net");
        assert_eq!(contact.priority, Some(800));
        assert_eq!(first.notes.len(), 2);
        assert_eq!(&*first.notes[0].text, "Don't Disturb Please!");
        assert_eq!(first.notes[0].lang.as_deref(), Some("en"));
        assert_eq!(first.notes[1].lang.as_deref(), Some("fr"));
        assert_eq!(first.timestamp.as_deref(), Some("2001-10-27T16:49:29Z"));
        assert_eq!(
            presence.tuples[1]
                .contact
                .as_ref()
                .and_then(|contact| contact.priority),
            Some(1_000)
        );
        assert_eq!(
            presence.notes,
            vec![Note::new("I'll be in Tokyo next week")]
        );
        assert!(presence.is_open());
        assert!(presence.person.is_none());
    }

    #[test]
    fn rpid_activities_are_read_from_the_person_and_its_note_is_not_one() {
        let presence = Presence::parse(RPID.as_bytes()).expect("a document");
        let person = presence.person.as_ref().expect("a person");
        assert_eq!(&*person.id, "p1");
        assert_eq!(presence.activities(), &[Activity::Away]);
        assert!(
            presence.notes.is_empty(),
            "the activities' note is not the document's"
        );
    }

    #[test]
    fn every_activity_of_the_subset_and_the_rest_by_name() {
        let body = "<presence entity=\"pres:a@example.com\"><person id=\"p\"><activities>\
<away/><busy/><on-the-phone/><meeting/><vacation/><meal/><other>Juggling</other>\
</activities></person></presence>";
        let presence = Presence::parse(body.as_bytes()).expect("a document");
        assert_eq!(
            presence.activities(),
            &[
                Activity::Away,
                Activity::Busy,
                Activity::OnThePhone,
                Activity::Meeting,
                Activity::Vacation,
                Activity::Unlisted("meal".into()),
                Activity::Other("Juggling".into()),
            ]
        );
    }

    #[test]
    fn a_document_written_here_reads_back_as_itself() {
        let mut tuple = Tuple::new("t1", Basic::Open);
        tuple.contact = Some(Contact {
            uri: "sip:alice@example.com".into(),
            priority: Some(500),
        });
        tuple.notes.push(Note {
            text: "Back <soon> & \"sure\"".into(),
            lang: Some("en".into()),
        });
        tuple.timestamp = Some("2026-09-29T10:00:00Z".into());
        let presence = Presence {
            entity: "sip:alice@example.com".into(),
            tuples: vec![tuple, Tuple::new("t2", Basic::Closed)],
            notes: vec![Note::new("it's me")],
            person: Some(Person {
                id: "p1".into(),
                activities: vec![
                    Activity::OnThePhone,
                    Activity::Meeting,
                    Activity::Unlisted("travel".into()),
                    Activity::Other("a & b".into()),
                ],
            }),
        };
        let written = presence.to_xml().expect("a document");
        assert_eq!(Presence::parse(&written).expect("it reads"), presence);
        let text = String::from_utf8(written).expect("UTF-8");
        assert!(text.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<presence"));
        assert!(text.contains("xmlns=\"urn:ietf:params:xml:ns:pidf\""));
        assert!(text.contains("xmlns:rpid=\"urn:ietf:params:xml:ns:pidf:rpid\""));
        assert!(text.contains("<contact priority=\"0.5\">sip:alice@example.com</contact>"));
        assert!(text.contains("Back &lt;soon&gt; &amp; &quot;sure&quot;"));
        assert!(text.contains("<rpid:on-the-phone/>"));
    }

    #[test]
    fn a_document_without_a_person_declares_no_rpid_namespace() {
        let mut presence = Presence::new("pres:bob@example.com");
        presence.tuples.push(Tuple::new("a", Basic::Closed));
        let text = String::from_utf8(presence.to_xml().expect("a document")).expect("UTF-8");
        assert!(!text.contains("rpid"));
        assert!(text.contains("<basic>closed</basic>"));
        assert!(
            !Presence::parse(text.as_bytes())
                .expect("it reads")
                .is_open()
        );
    }

    #[test]
    fn what_cannot_be_written_correctly_is_not_written() {
        let mut presence = Presence::new("");
        assert_eq!(
            presence.to_xml(),
            Err(PresenceError::Unwritable("an empty entity"))
        );
        presence = Presence::new("pres:a@example.com");
        presence.tuples.push(Tuple::new("1abc", Basic::Open));
        assert_eq!(
            presence.to_xml(),
            Err(PresenceError::Unwritable("an id that is not an XML name"))
        );
        presence.tuples = vec![Tuple::new("x", Basic::Open), Tuple::new("x", Basic::Open)];
        assert_eq!(
            presence.to_xml(),
            Err(PresenceError::Unwritable("an id used twice"))
        );
        presence.tuples = vec![Tuple::new("x", Basic::Open)];
        presence.person = Some(Person {
            id: "x".into(),
            activities: Vec::new(),
        });
        assert_eq!(
            presence.to_xml(),
            Err(PresenceError::Unwritable("an id used twice")),
            "a person and a tuple share one ID space"
        );
        presence.person = Some(Person {
            id: "p".into(),
            activities: vec![Activity::Unlisted("a><b".into())],
        });
        assert_eq!(
            presence.to_xml(),
            Err(PresenceError::Unwritable(
                "an activity name that is not an XML name"
            ))
        );
        presence.person = None;
        let mut tuple = Tuple::new("x", Basic::Open);
        tuple.contact = Some(Contact {
            uri: "sip:a@example.com".into(),
            priority: Some(1_001),
        });
        presence.tuples = vec![tuple];
        assert_eq!(
            presence.to_xml(),
            Err(PresenceError::Unwritable("a priority above 1"))
        );
    }

    #[test]
    fn a_document_missing_what_the_schema_requires_is_refused() {
        for (body, expected) in [
            (
                "<presence><tuple id=\"a\"><status/></tuple></presence>",
                PresenceError::Malformed("no entity"),
            ),
            (
                "<presence entity=\"pres:a@example.com\"><tuple><status/></tuple></presence>",
                PresenceError::Malformed("a tuple with no id"),
            ),
            (
                "<presence entity=\"pres:a@example.com\"><tuple id=\"a\"/></presence>",
                PresenceError::Malformed("a tuple with no status"),
            ),
            (
                "<presence entity=\"pres:a@example.com\"><tuple id=\"a\"><status>\
<basic>ajar</basic></status></tuple></presence>",
                PresenceError::Malformed("basic is neither open nor closed"),
            ),
            (
                "<presence entity=\"pres:a@example.com\"><tuple id=\"a\"><status/>\
<contact priority=\"2\">sip:a@example.com</contact></tuple></presence>",
                PresenceError::Malformed("priority is not a qvalue"),
            ),
            (
                "<presence entity=\"pres:a@example.com\"><person><activities/></person>\
</presence>",
                PresenceError::Malformed("a person with no id"),
            ),
            ("<dialog-info version=\"1\"/>", PresenceError::NotPresence),
            (
                "<!DOCTYPE presence><presence entity=\"x\"/>",
                PresenceError::Refused("a declaration or CDATA section"),
            ),
        ] {
            assert_eq!(Presence::parse(body.as_bytes()), Err(expected), "{body}");
        }
    }

    #[test]
    fn more_tuples_than_the_bound_are_refused() {
        let mut body = String::from("<presence entity=\"pres:a@example.com\">");
        for n in 0..=MAX_TUPLES {
            body.push_str("<tuple id=\"t");
            body.push_str(&n.to_string());
            body.push_str("\"><status/></tuple>");
        }
        body.push_str("</presence>");
        assert_eq!(
            Presence::parse(body.as_bytes()),
            Err(PresenceError::TooLarge("tuples"))
        );
    }

    #[test]
    fn qvalues_are_read_and_written_by_rfc_3261s_grammar() {
        for (text, thousandths) in [
            ("0", 0),
            ("0.", 0),
            ("0.8", 800),
            ("0.05", 50),
            ("0.123", 123),
            ("1", 1_000),
            ("1.0", 1_000),
            ("1.000", 1_000),
        ] {
            assert_eq!(qvalue(text), Ok(thousandths), "{text}");
        }
        for text in ["", "2", "1.5", "0.1234", "0.a", ".5", "-0", "01"] {
            assert!(qvalue(text).is_err(), "{text}");
        }
        for (thousandths, text) in [(0, "0"), (800, "0.8"), (50, "0.05"), (1_000, "1")] {
            assert_eq!(format_qvalue(thousandths), text);
        }
    }
}
