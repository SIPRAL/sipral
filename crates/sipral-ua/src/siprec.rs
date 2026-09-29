// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! SIPREC: the metadata of a recorded call, and the pieces of the INVITE that
//! offers it to a recorder.
//!
//! A session recording client (SRC) sends a session recording server (SRS) a
//! recording session: an INVITE whose SDP carries the recorded media and whose
//! second body part says what that media is (RFC 7866 §6.1). The model of
//! that second part is RFC 7865's — a recording session records communication
//! sessions, grouped, with participants who send and receive streams — and so
//! is its format: the XML of RFC 7865's schema, in the
//! `urn:ietf:params:xml:ns:recording:1` namespace, carried as
//! `application/rs-metadata+xml`.
//!
//! [`RecordingMetadata`](crate::siprec::RecordingMetadata) is that
//! document, one field per element. It is written with
//! [`RecordingMetadata::to_xml`](crate::siprec::RecordingMetadata::to_xml)
//! and read with
//! [`RecordingMetadata::parse`](crate::siprec::RecordingMetadata::parse);
//! [`RecordedCall`](crate::siprec::RecordedCall) builds the usual one, a
//! single call and its parties, with every association filled in. The helpers
//! at the bottom are the INVITE's: the `multipart/mixed` body with the SDP and
//! the metadata, `Content-Disposition: recording-session`, the `+sip.src`
//! feature tag in `Contact` and the `siprec` option tag.
//!
//! **The reader is the one `application/dialog-info+xml` goes through**, for
//! the same reason: the bytes come from the network, and a reader that has no
//! document type declaration, no entities beyond XML's five and no CDATA has
//! nothing in it to exploit. Elements this module does not know are skipped
//! with their content, which is where RFC 7865's extension data lives. As with
//! dialog information, namespaces are matched by local name, except that a
//! root that declares a default namespace other than the recording one is not
//! a recording document.
//!
//! **Partial metadata is read, not merged.** A `partial` document carries only
//! what changed since the last one (RFC 7866), so its references may name
//! elements it does not hold.
//! [`RecordingMetadata::validate`](crate::siprec::RecordingMetadata::validate)
//! resolves references for `complete` documents only.

use sipral_core::msg::{
    BuiltMultipart, MultipartBuilder, MultipartError, NameAddrRef, Part, RawMessage,
};
use sipral_core::sdp::SessionDescription;

use crate::dialoginfo::{Attributes, DialogInfoError, Node, Reader, as_str, local_name, unescape};

/// The media type of recording metadata, as RFC 7865 §5 names it and as
/// this crate writes it. RFC 7866 §9 and its examples call the same body
/// `application/rs-metadata`, which [`read_recording_offer`] accepts too.
pub const METADATA_CONTENT_TYPE: &str = "application/rs-metadata+xml";
/// The namespace of recording metadata (RFC 7865).
pub const NAMESPACE: &str = "urn:ietf:params:xml:ns:recording:1";
/// The disposition of the metadata part of a recording session's body
/// (RFC 7866 §9).
pub const RECORDING_SESSION_DISPOSITION: &str = "recording-session";
/// The option tag of a recording session, in `Require` or `Supported`
/// (RFC 7866 §6.1).
pub const OPTION_TAG: &str = "siprec";
/// The feature tag an SRC puts in its `Contact` (RFC 7866 §6.1).
pub const SRC_FEATURE_TAG: &str = "+sip.src";
/// The feature tag an SRS puts in its `Contact` (RFC 7866 §6.2).
pub const SRS_FEATURE_TAG: &str = "+sip.srs";

/// The largest metadata document that will be read.
const MAX_BYTES: usize = 64 * 1024;
/// How deep elements may nest, extensions included. The schema's deepest
/// path is `recording` → `participant` → `nameID` → `name`, which is four.
const MAX_DEPTH: usize = 16;
/// How many elements will be read before the document is refused.
const MAX_ELEMENTS: usize = 4_096;
/// How many groups, sessions, participants, streams and associations one
/// document may carry, all counted together.
const MAX_ITEMS: usize = 512;
/// The longest text content kept, and the longest value written once
/// escaped: the tokeniser takes no text or attribute value longer.
const MAX_TEXT: usize = 1_024;

/// Why recording metadata could not be read or written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SiprecError {
    /// The body is not XML, or the markup does not close.
    Malformed(&'static str),
    /// A construct the reader refuses on sight: a document type declaration,
    /// an entity, a CDATA section.
    Refused(&'static str),
    /// One of the bounds in this module was reached.
    TooLarge(&'static str),
    /// Text that is not UTF-8.
    NotUtf8,
    /// The root element is not `recording`, or declares a default namespace
    /// other than the recording one. A prefixed root's namespace is not
    /// looked up.
    NotRecording,
    /// An element lacks an attribute the schema requires.
    MissingAttribute(&'static str),
    /// A `complete` document refers to an identifier it does not define.
    UnknownReference(&'static str),
    /// A value cannot be written into the document.
    IllegalValue(&'static str),
    /// A stream's label is on no `a=label` line of the SDP.
    UnknownLabel,
    /// The multipart body could not be built or read.
    Multipart(MultipartError),
    /// The message has no body part of the given kind.
    MissingPart(&'static str),
}

impl core::fmt::Display for SiprecError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match *self {
            Self::Malformed(what) => write!(f, "malformed recording metadata: {what}"),
            Self::Refused(what) => write!(f, "refused: {what}"),
            Self::TooLarge(what) => write!(f, "too large: {what}"),
            Self::NotUtf8 => f.write_str("not UTF-8"),
            Self::NotRecording => f.write_str("not a recording metadata document"),
            Self::MissingAttribute(name) => write!(f, "missing attribute {name}"),
            Self::UnknownReference(what) => write!(f, "{what} refers to nothing"),
            Self::IllegalValue(what) => write!(f, "illegal value: {what}"),
            Self::UnknownLabel => f.write_str("a stream label is not in the SDP"),
            Self::Multipart(e) => write!(f, "multipart body: {e}"),
            Self::MissingPart(what) => write!(f, "no {what} part"),
        }
    }
}

impl core::error::Error for SiprecError {}

impl From<DialogInfoError> for SiprecError {
    fn from(e: DialogInfoError) -> Self {
        match e {
            DialogInfoError::Malformed(what) => Self::Malformed(what),
            DialogInfoError::Refused(what) => Self::Refused(what),
            DialogInfoError::TooLarge(what) => Self::TooLarge(what),
            DialogInfoError::NotUtf8 => Self::NotUtf8,
            DialogInfoError::NotDialogInfo => Self::NotRecording,
        }
    }
}

impl From<MultipartError> for SiprecError {
    fn from(e: MultipartError) -> Self {
        Self::Multipart(e)
    }
}

/// Whether a document is the whole metadata or a change to it (RFC 7865,
/// RFC 7866).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum DataMode {
    /// Everything the recording session has.
    #[default]
    Complete,
    /// Only what changed since the previous document.
    Partial,
}

impl DataMode {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }
}

/// A communication session group: sessions recorded together (RFC 7865).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Group {
    /// `group_id`.
    pub id: String,
    /// When the group was associated with the recording session.
    pub associate_time: Option<String>,
    /// When it stopped being.
    pub disassociate_time: Option<String>,
}

/// A communication session: one call being recorded (RFC 7865).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Session {
    /// `session_id`.
    pub id: String,
    /// The call's `Session-ID` values (RFC 7989), as written.
    pub sip_session_ids: Vec<String>,
    /// The group the session belongs to.
    pub group_ref: Option<String>,
    /// When the session started.
    pub start_time: Option<String>,
    /// When it ended.
    pub end_time: Option<String>,
}

/// One name of a participant, in one language.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Name {
    /// `xml:lang`.
    pub lang: Option<String>,
    /// The name.
    pub text: String,
}

/// A participant's address of record and the names it goes by.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NameId {
    /// `aor`: the address of record.
    pub aor: String,
    /// The display names.
    pub names: Vec<Name>,
}

/// A participant: someone whose media is recorded (RFC 7865).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Participant {
    /// `participant_id`.
    pub id: String,
    /// Who the participant is.
    pub name_ids: Vec<NameId>,
}

/// A media stream (RFC 7865).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stream {
    /// `stream_id`.
    pub id: String,
    /// The session the stream belongs to.
    pub session_id: String,
    /// The SDP `a=label` (RFC 4574) of the media line that carries it.
    pub label: Option<String>,
}

/// When a session was, or stopped being, part of the recording session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionRecordingAssoc {
    /// The session.
    pub session_id: String,
    /// When it was associated.
    pub associate_time: Option<String>,
    /// When it stopped being.
    pub disassociate_time: Option<String>,
}

/// When a participant joined, or left, a session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParticipantSessionAssoc {
    /// The participant.
    pub participant_id: String,
    /// The session.
    pub session_id: String,
    /// When the participant joined.
    pub associate_time: Option<String>,
    /// When the participant left.
    pub disassociate_time: Option<String>,
}

/// Which streams a participant sends and which it receives.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ParticipantStreamAssoc {
    /// The participant.
    pub participant_id: String,
    /// The streams it sends.
    pub send: Vec<String>,
    /// The streams it receives.
    pub recv: Vec<String>,
}

/// One recording metadata document (RFC 7865).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordingMetadata {
    /// `datamode`. Absent from a document, it is read as complete.
    pub data_mode: DataMode,
    /// `group` elements.
    pub groups: Vec<Group>,
    /// `session` elements.
    pub sessions: Vec<Session>,
    /// `participant` elements.
    pub participants: Vec<Participant>,
    /// `stream` elements.
    pub streams: Vec<Stream>,
    /// `sessionrecordingassoc` elements.
    pub session_recording: Vec<SessionRecordingAssoc>,
    /// `participantsessionassoc` elements.
    pub participant_sessions: Vec<ParticipantSessionAssoc>,
    /// `participantstreamassoc` elements.
    pub participant_streams: Vec<ParticipantStreamAssoc>,
}

impl RecordingMetadata {
    /// An empty document of this mode.
    #[must_use]
    pub fn new(data_mode: DataMode) -> Self {
        Self {
            data_mode,
            ..Self::default()
        }
    }

    /// Whether every reference in a `complete` document resolves: a
    /// session's group, a stream's session, and every association's
    /// participant, session and streams. A `partial` one always passes.
    ///
    /// # Errors
    /// [`SiprecError::UnknownReference`], naming the reference.
    pub fn validate(&self) -> Result<(), SiprecError> {
        if self.data_mode == DataMode::Partial {
            return Ok(());
        }
        let group = |id: &str| self.groups.iter().any(|g| g.id == id);
        let session = |id: &str| self.sessions.iter().any(|s| s.id == id);
        let participant = |id: &str| self.participants.iter().any(|p| p.id == id);
        let stream = |id: &str| self.streams.iter().any(|s| s.id == id);
        let check = |ok: bool, what| {
            if ok {
                Ok(())
            } else {
                Err(SiprecError::UnknownReference(what))
            }
        };
        for s in &self.sessions {
            check(s.group_ref.as_deref().is_none_or(group), "group-ref")?;
        }
        for s in &self.streams {
            check(session(&s.session_id), "stream session_id")?;
        }
        for a in &self.session_recording {
            check(session(&a.session_id), "sessionrecordingassoc")?;
        }
        for a in &self.participant_sessions {
            check(participant(&a.participant_id), "participantsessionassoc")?;
            check(session(&a.session_id), "participantsessionassoc")?;
        }
        for a in &self.participant_streams {
            check(participant(&a.participant_id), "participantstreamassoc")?;
            check(
                a.send.iter().chain(&a.recv).all(|id| stream(id)),
                "participantstreamassoc stream",
            )?;
        }
        Ok(())
    }

    /// Whether every stream's label names a media line of `sdp`: RFC 7866
    /// ties the two together by `a=label` (RFC 4574).
    ///
    /// # Errors
    /// [`SiprecError::UnknownLabel`].
    pub fn check_labels(&self, sdp: &SessionDescription) -> Result<(), SiprecError> {
        let known = |label: &str| {
            sdp.media.iter().any(|m| {
                m.attribute("label")
                    .and_then(|a| a.value.as_deref())
                    .is_some_and(|value| value.trim() == label)
            })
        };
        if self
            .streams
            .iter()
            .filter_map(|s| s.label.as_deref())
            .all(known)
        {
            Ok(())
        } else {
            Err(SiprecError::UnknownLabel)
        }
    }

    /// The document, as XML.
    ///
    /// # Errors
    /// [`SiprecError::UnknownReference`] as [`Self::validate`] finds it, and
    /// [`SiprecError::IllegalValue`] for an empty identifier or a value XML
    /// cannot carry.
    pub fn to_xml(&self) -> Result<String, SiprecError> {
        self.validate()?;
        let mut w = Writer::default();
        w.raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        w.raw("<recording xmlns=\"");
        w.raw(NAMESPACE);
        w.raw("\">\n");
        w.leaf(1, "datamode", &[], self.data_mode.as_str())?;
        for g in &self.groups {
            w.open(1, "group", &[("group_id", &g.id)])?;
            w.optional(2, "associate-time", g.associate_time.as_deref())?;
            w.optional(2, "disassociate-time", g.disassociate_time.as_deref())?;
            w.close(1, "group");
        }
        for s in &self.sessions {
            w.open(1, "session", &[("session_id", &s.id)])?;
            for id in &s.sip_session_ids {
                w.leaf(2, "sipSessionID", &[], id)?;
            }
            w.optional(2, "group-ref", s.group_ref.as_deref())?;
            w.optional(2, "start-time", s.start_time.as_deref())?;
            w.optional(2, "end-time", s.end_time.as_deref())?;
            w.close(1, "session");
        }
        for p in &self.participants {
            w.open(1, "participant", &[("participant_id", &p.id)])?;
            for n in &p.name_ids {
                w.open(2, "nameID", &[("aor", &n.aor)])?;
                for name in &n.names {
                    match name.lang.as_deref() {
                        Some(lang) => w.leaf(3, "name", &[("xml:lang", lang)], &name.text)?,
                        None => w.leaf(3, "name", &[], &name.text)?,
                    }
                }
                w.close(2, "nameID");
            }
            w.close(1, "participant");
        }
        for s in &self.streams {
            w.open(
                1,
                "stream",
                &[("stream_id", &s.id), ("session_id", &s.session_id)],
            )?;
            w.optional(2, "label", s.label.as_deref())?;
            w.close(1, "stream");
        }
        for a in &self.session_recording {
            w.open(1, "sessionrecordingassoc", &[("session_id", &a.session_id)])?;
            w.optional(2, "associate-time", a.associate_time.as_deref())?;
            w.optional(2, "disassociate-time", a.disassociate_time.as_deref())?;
            w.close(1, "sessionrecordingassoc");
        }
        for a in &self.participant_sessions {
            w.open(
                1,
                "participantsessionassoc",
                &[
                    ("participant_id", &a.participant_id),
                    ("session_id", &a.session_id),
                ],
            )?;
            w.optional(2, "associate-time", a.associate_time.as_deref())?;
            w.optional(2, "disassociate-time", a.disassociate_time.as_deref())?;
            w.close(1, "participantsessionassoc");
        }
        for a in &self.participant_streams {
            w.open(
                1,
                "participantstreamassoc",
                &[("participant_id", &a.participant_id)],
            )?;
            for id in &a.send {
                w.leaf(2, "send", &[], id)?;
            }
            for id in &a.recv {
                w.leaf(2, "recv", &[], id)?;
            }
            w.close(1, "participantstreamassoc");
        }
        w.raw("</recording>\n");
        Ok(w.out)
    }

    /// Read one document.
    ///
    /// Unknown elements are skipped with everything inside them. Identifiers
    /// are not resolved here; see [`Self::validate`].
    ///
    /// # Errors
    /// See [`SiprecError`]. Nothing is returned from a document that fails.
    pub fn parse(body: &[u8]) -> Result<Self, SiprecError> {
        if body.len() > MAX_BYTES {
            return Err(SiprecError::TooLarge("document"));
        }
        Walk::default().run(Reader::new(body))
    }
}

// -- building one for a call ---------------------------------------------------

/// One stream a party of a recorded call sends.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordedStream {
    /// `stream_id`.
    pub id: String,
    /// The SDP `a=label` of the media line the SRC forks it on.
    pub label: String,
}

/// One party of a recorded call.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordedParty {
    /// `participant_id`.
    pub id: String,
    /// The party's address of record.
    pub aor: String,
    /// The party's display name, if one is known.
    pub name: Option<String>,
    /// The streams this party sends.
    pub sends: Vec<RecordedStream>,
}

/// A call being recorded, from which [`RecordingMetadata`] is built.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordedCall {
    /// `session_id` of the communication session.
    pub session_id: String,
    /// The call's `Session-ID` (RFC 7989), when it has one.
    pub sip_session_id: Option<String>,
    /// `group_id`, when the call is recorded as part of a group.
    pub group_id: Option<String>,
    /// When recording began, as an XML `dateTime`: every association's
    /// `associate-time`.
    pub started: Option<String>,
    /// The parties.
    pub parties: Vec<RecordedParty>,
}

impl RecordedCall {
    /// The `complete` metadata of this call.
    ///
    /// Each party sends its own streams and receives every other party's,
    /// which is what a call between them is (RFC 7865).
    #[must_use]
    pub fn metadata(&self) -> RecordingMetadata {
        let mut m = RecordingMetadata::new(DataMode::Complete);
        if let Some(group) = &self.group_id {
            m.groups.push(Group {
                id: group.clone(),
                associate_time: self.started.clone(),
                disassociate_time: None,
            });
        }
        m.sessions.push(Session {
            id: self.session_id.clone(),
            sip_session_ids: self.sip_session_id.iter().cloned().collect(),
            group_ref: self.group_id.clone(),
            start_time: None,
            end_time: None,
        });
        m.session_recording.push(SessionRecordingAssoc {
            session_id: self.session_id.clone(),
            associate_time: self.started.clone(),
            disassociate_time: None,
        });
        for party in &self.parties {
            m.participants.push(Participant {
                id: party.id.clone(),
                name_ids: vec![NameId {
                    aor: party.aor.clone(),
                    names: party
                        .name
                        .iter()
                        .map(|text| Name {
                            lang: None,
                            text: text.clone(),
                        })
                        .collect(),
                }],
            });
            for stream in &party.sends {
                m.streams.push(Stream {
                    id: stream.id.clone(),
                    session_id: self.session_id.clone(),
                    label: Some(stream.label.clone()),
                });
            }
            m.participant_sessions.push(ParticipantSessionAssoc {
                participant_id: party.id.clone(),
                session_id: self.session_id.clone(),
                associate_time: self.started.clone(),
                disassociate_time: None,
            });
            m.participant_streams.push(ParticipantStreamAssoc {
                participant_id: party.id.clone(),
                send: party.sends.iter().map(|s| s.id.clone()).collect(),
                recv: self
                    .parties
                    .iter()
                    .filter(|other| other.id != party.id)
                    .flat_map(|other| other.sends.iter().map(|s| s.id.clone()))
                    .collect(),
            });
        }
        m
    }
}

/// A metadata identifier from 128 bits, as RFC 7865's schema types them: a UUID
/// (RFC 4122) in base64 (RFC 4648 §4).
#[must_use]
pub fn metadata_id(uuid: [u8; 16]) -> String {
    base64(&uuid)
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let symbol = |index: u32| {
        ALPHABET
            .get(usize::try_from(index & 0x3f).unwrap_or_default())
            .map_or('=', |byte| char::from(*byte))
    };
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let [a, b, c] = [0, 1, 2].map(|i| u32::from(chunk.get(i).copied().unwrap_or(0)));
        let group = (a << 16) | (b << 8) | c;
        out.push(symbol(group >> 18));
        out.push(symbol(group >> 12));
        out.push(if chunk.len() > 1 {
            symbol(group >> 6)
        } else {
            '='
        });
        out.push(if chunk.len() > 2 { symbol(group) } else { '=' });
    }
    out
}

// -- the recording session's INVITE --------------------------------------------

/// The body of a recording session's INVITE: `multipart/mixed` with the SDP
/// first and the metadata second, with `Content-Disposition:
/// recording-session` (RFC 7866 §9.1).
///
/// # Errors
/// What [`RecordingMetadata::to_xml`] refuses, and a body the multipart
/// builder cannot write.
pub fn recording_session_body(
    sdp: &[u8],
    metadata: &RecordingMetadata,
) -> Result<BuiltMultipart, SiprecError> {
    let xml = metadata.to_xml()?;
    written_session_body(sdp, &xml)
}

/// [`recording_session_body`] for metadata already written.
pub(crate) fn written_session_body(sdp: &[u8], xml: &str) -> Result<BuiltMultipart, SiprecError> {
    Ok(MultipartBuilder::mixed()
        .part(Part::new("application/sdp", sdp))
        .part(
            Part::new(METADATA_CONTENT_TYPE, xml.as_bytes())
                .disposition(RECORDING_SESSION_DISPOSITION),
        )
        .build()?)
}

/// A `Contact` value with the SRC feature tag added (RFC 7866 §6.1), as in
/// `<sip:src@192.0.2.1>;+sip.src`. A value that already names it is
/// returned as it is, whatever value it gives it: a second would contradict
/// the first.
#[must_use]
pub fn with_src_feature_tag(contact: &str) -> String {
    let already =
        NameAddrRef::parse(contact.as_bytes()).is_ok_and(|addr| addr.params().has(SRC_FEATURE_TAG));
    if already {
        contact.to_owned()
    } else {
        format!("{contact};{SRC_FEATURE_TAG}")
    }
}

/// Whether a request's `Require` carries the `siprec` option tag, as an
/// SRC's or an SRS's INVITE of a recording session must (RFC 7866 §6.1,
/// §6.2). It is half of what makes one: RFC 7866 §6.2 has an SRS treat a
/// new INVITE as a recording session only when its `Contact` also carries
/// [`SRC_FEATURE_TAG`] ([`contact_has_feature_tag`]), and §6.1 has an SRC
/// ask the same of [`SRS_FEATURE_TAG`].
#[must_use]
pub fn requires_siprec(message: &RawMessage<'_>) -> bool {
    message.require().has(OPTION_TAG)
}

/// Whether a message's `Supported` carries the `siprec` option tag.
#[must_use]
pub fn supports_siprec(message: &RawMessage<'_>) -> bool {
    message.supported().has(OPTION_TAG)
}

/// Whether the message's `Contact` carries the given feature tag,
/// [`SRC_FEATURE_TAG`] or [`SRS_FEATURE_TAG`], as true.
///
/// Both are boolean feature tags (RFC 3840): bare or `="TRUE"` they are
/// true, and `="FALSE"` or `="!TRUE"` says the contact is not one.
#[must_use]
pub fn contact_has_feature_tag(message: &RawMessage<'_>, tag: &str) -> bool {
    let Ok(contacts) = message.contact() else {
        return false;
    };
    match contacts {
        sipral_core::msg::Contacts::Star => false,
        sipral_core::msg::Contacts::Addrs(addrs) => addrs
            .into_iter()
            .any(|addr| addr.is_ok_and(|addr| boolean_feature(&addr.params(), tag))),
    }
}

/// Whether a boolean feature parameter is present and true: `tag-value-list`
/// holds `TRUE` or `!FALSE` (RFC 3840's `tag-value = ["!"] (... / boolean)`).
fn boolean_feature(params: &sipral_core::msg::Params<'_>, tag: &str) -> bool {
    match params.get(tag) {
        None => false,
        Some(value) if value.is_empty() => true,
        Some(value) => value.split(|byte| *byte == b',').any(|item| {
            let item = sipral_core::msg::trim(item);
            item.eq_ignore_ascii_case(b"TRUE") || item.eq_ignore_ascii_case(b"!FALSE")
        }),
    }
}

/// What a recording session's INVITE offers: the SDP and the metadata.
#[derive(Clone, Debug)]
pub struct RecordingOffer<'a> {
    /// The SDP part, as it was carried.
    pub sdp: &'a [u8],
    /// The metadata part, read.
    pub metadata: RecordingMetadata,
}

/// Read the body of a recording session's INVITE: the SDP part and the
/// `recording-session` metadata part (RFC 7866 §9.1).
///
/// A metadata part is found by its disposition, and failing that by its
/// type, `application/rs-metadata+xml` (RFC 7865 §5) or the
/// `application/rs-metadata` RFC 7866 §9 writes. Only `multipart` bodies
/// are read; an INVITE with the SDP alone carries its metadata later, if at
/// all (RFC 7866 §9.1).
///
/// # Errors
/// [`SiprecError::MissingPart`] when either part is absent, and whatever the
/// body or the metadata does not survive.
pub fn read_recording_offer<'a>(
    message: &RawMessage<'a>,
) -> Result<RecordingOffer<'a>, SiprecError> {
    let content_type = message
        .content_type()
        .map_err(|_| SiprecError::MissingPart("multipart"))?;
    let body = sipral_core::msg::Multipart::parse(&content_type, message.body())?;
    let sdp = body
        .find("application", "sdp")
        .ok_or(SiprecError::MissingPart("application/sdp"))?;
    let metadata = body
        .parts()
        .iter()
        .find(|part| {
            part.disposition()
                .is_some_and(|d| d.is(RECORDING_SESSION_DISPOSITION))
        })
        .or_else(|| body.find("application", "rs-metadata+xml"))
        .or_else(|| body.find("application", "rs-metadata"))
        .ok_or(SiprecError::MissingPart(METADATA_CONTENT_TYPE))?;
    Ok(RecordingOffer {
        sdp: sdp.body(),
        metadata: RecordingMetadata::parse(metadata.body())?,
    })
}

// -- writing -----------------------------------------------------------------

#[derive(Default)]
struct Writer {
    out: String,
}

impl Writer {
    fn raw(&mut self, text: &str) {
        self.out.push_str(text);
    }

    fn indent(&mut self, depth: usize) {
        for _ in 0..depth {
            self.out.push_str("  ");
        }
    }

    fn start(
        &mut self,
        depth: usize,
        name: &str,
        attributes: &[(&str, &str)],
    ) -> Result<(), SiprecError> {
        self.indent(depth);
        self.out.push('<');
        self.out.push_str(name);
        for (key, value) in attributes {
            if value.is_empty() {
                return Err(SiprecError::IllegalValue("an empty attribute"));
            }
            self.out.push(' ');
            self.out.push_str(key);
            self.out.push_str("=\"");
            self.escaped(value, true)?;
            self.out.push('"');
        }
        self.out.push('>');
        Ok(())
    }

    fn open(
        &mut self,
        depth: usize,
        name: &str,
        attributes: &[(&str, &str)],
    ) -> Result<(), SiprecError> {
        self.start(depth, name, attributes)?;
        self.out.push('\n');
        Ok(())
    }

    fn close(&mut self, depth: usize, name: &str) {
        self.indent(depth);
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push_str(">\n");
    }

    fn leaf(
        &mut self,
        depth: usize,
        name: &str,
        attributes: &[(&str, &str)],
        text: &str,
    ) -> Result<(), SiprecError> {
        self.start(depth, name, attributes)?;
        self.escaped(text, false)?;
        self.out.push_str("</");
        self.out.push_str(name);
        self.out.push_str(">\n");
        Ok(())
    }

    fn optional(
        &mut self,
        depth: usize,
        name: &str,
        text: Option<&str>,
    ) -> Result<(), SiprecError> {
        match text {
            Some(text) => self.leaf(depth, name, &[], text),
            None => Ok(()),
        }
    }

    /// XML 1.0 §2.4 and §2.2: markup escaped, and no character a document
    /// cannot hold. A reader rewrites a CR before anything else sees it
    /// (§2.11), and every TAB, LF and CR of an attribute value into a space
    /// (§3.3.3); those are written as character references, which it keeps.
    ///
    /// The bound is on the value as written: the reader bounds the escaped
    /// bytes, and `&` is five of them.
    fn escaped(&mut self, text: &str, attribute: bool) -> Result<(), SiprecError> {
        if text.len() > MAX_TEXT {
            return Err(SiprecError::IllegalValue("a value too long to read back"));
        }
        let start = self.out.len();
        for c in text.chars() {
            match c {
                '&' => self.out.push_str("&amp;"),
                '<' => self.out.push_str("&lt;"),
                '>' => self.out.push_str("&gt;"),
                '"' => self.out.push_str("&quot;"),
                '\'' => self.out.push_str("&apos;"),
                '\r' => self.out.push_str("&#13;"),
                '\t' if attribute => self.out.push_str("&#9;"),
                '\n' if attribute => self.out.push_str("&#10;"),
                '\t' | '\n' => self.out.push(c),
                c if c.is_control() => {
                    return Err(SiprecError::IllegalValue("a control character"));
                }
                // §2.2's Char skips these two, and a Rust string can hold them
                '\u{FFFE}' | '\u{FFFF}' => {
                    return Err(SiprecError::IllegalValue("a character XML excludes"));
                }
                c => self.out.push(c),
            }
        }
        if self.out.len().saturating_sub(start) > MAX_TEXT {
            return Err(SiprecError::IllegalValue("a value too long to read back"));
        }
        Ok(())
    }
}

// -- reading -----------------------------------------------------------------

/// Which value the text of the open element goes into.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    DataMode,
    GroupAssociate,
    GroupDisassociate,
    SipSessionId,
    GroupRef,
    StartTime,
    EndTime,
    Label,
    RecordingAssociate,
    RecordingDisassociate,
    ParticipantAssociate,
    ParticipantDisassociate,
    Send,
    Recv,
    Name,
}

#[derive(Default)]
struct Walk {
    metadata: RecordingMetadata,
    root: bool,
    items: usize,
    /// The element whose text is wanted, and how deep it is.
    target: Option<(Target, usize)>,
    text: String,
}

impl Walk {
    fn run(mut self, mut reader: Reader<'_>) -> Result<RecordingMetadata, SiprecError> {
        let mut path: Vec<&[u8]> = Vec::new();
        for _ in 0..MAX_ELEMENTS {
            let Some(node) = reader.next()? else {
                if !self.root {
                    return Err(SiprecError::NotRecording);
                }
                if !path.is_empty() {
                    return Err(SiprecError::Malformed("an element never closed"));
                }
                return Ok(self.metadata);
            };
            match node {
                Node::Open(element) => {
                    if path.len() >= MAX_DEPTH {
                        return Err(SiprecError::TooLarge("nesting"));
                    }
                    if self.root && path.is_empty() {
                        return Err(SiprecError::Malformed("a second root element"));
                    }
                    let name = local_name(element.name);
                    path.push(name);
                    self.open(&path, element.name, element.attributes)?;
                    if element.empty {
                        self.close(path.len())?;
                        path.pop();
                    }
                }
                Node::Close(name) => {
                    if path.last().copied() != Some(local_name(name)) {
                        return Err(SiprecError::Malformed("closing tag does not match"));
                    }
                    self.close(path.len())?;
                    path.pop();
                }
                Node::Text(raw) => {
                    if self.target.is_some_and(|(_, depth)| depth == path.len()) {
                        let text = unescape(raw)?;
                        let text = as_str(&text)?;
                        if self.text.len() + text.len() > MAX_TEXT {
                            return Err(SiprecError::TooLarge("text"));
                        }
                        self.text.push_str(text);
                    }
                }
            }
        }
        Err(SiprecError::TooLarge("element count"))
    }

    fn count(&mut self) -> Result<(), SiprecError> {
        self.items += 1;
        if self.items > MAX_ITEMS {
            return Err(SiprecError::TooLarge("item count"));
        }
        Ok(())
    }

    fn open(
        &mut self,
        path: &[&[u8]],
        qualified: &[u8],
        attributes: Attributes<'_>,
    ) -> Result<(), SiprecError> {
        let depth = path.len();
        let Some(&name) = path.last() else {
            return Ok(());
        };
        if depth == 1 {
            if name != b"recording" {
                return Err(SiprecError::NotRecording);
            }
            // a default namespace on an unprefixed root is a claim about what
            // this document is; any other is a different vocabulary
            if !qualified.contains(&b':')
                && let Some(ns) = attributes.value("xmlns")?
                && ns != NAMESPACE.as_bytes()
            {
                return Err(SiprecError::NotRecording);
            }
            self.root = true;
            return Ok(());
        }
        let parent = path.get(depth - 2).copied().unwrap_or_default();
        let grandparent = depth.checked_sub(3).and_then(|i| path.get(i)).copied();
        let target = if depth == 2 {
            self.open_item(name, attributes)?
        } else {
            self.open_child((depth, parent, name), grandparent, attributes)?
        };
        if let Some(target) = target {
            self.target = Some((target, depth));
            self.text.clear();
        }
        Ok(())
    }

    /// A child of `recording`: one of the schema's items, or `datamode`.
    fn open_item(
        &mut self,
        name: &[u8],
        attributes: Attributes<'_>,
    ) -> Result<Option<Target>, SiprecError> {
        let required = |attr: &'static str| -> Result<String, SiprecError> {
            attributes
                .text(attr)?
                .map(String::from)
                .ok_or(SiprecError::MissingAttribute(attr))
        };
        let m = &mut self.metadata;
        match name {
            b"datamode" => return Ok(Some(Target::DataMode)),
            b"group" => m.groups.push(Group {
                id: required("group_id")?,
                ..Group::default()
            }),
            b"session" => m.sessions.push(Session {
                id: required("session_id")?,
                ..Session::default()
            }),
            b"participant" => m.participants.push(Participant {
                id: required("participant_id")?,
                ..Participant::default()
            }),
            b"stream" => m.streams.push(Stream {
                id: required("stream_id")?,
                session_id: required("session_id")?,
                label: None,
            }),
            b"sessionrecordingassoc" => m.session_recording.push(SessionRecordingAssoc {
                session_id: required("session_id")?,
                ..SessionRecordingAssoc::default()
            }),
            b"participantsessionassoc" => {
                m.participant_sessions.push(ParticipantSessionAssoc {
                    participant_id: required("participant_id")?,
                    session_id: required("session_id")?,
                    ..ParticipantSessionAssoc::default()
                });
            }
            b"participantstreamassoc" => m.participant_streams.push(ParticipantStreamAssoc {
                participant_id: required("participant_id")?,
                ..ParticipantStreamAssoc::default()
            }),
            _ => return Ok(None),
        }
        self.count()?;
        Ok(None)
    }

    /// An element inside one of the items: `(depth, parent, name)`.
    fn open_child(
        &mut self,
        (depth, parent, name): (usize, &[u8], &[u8]),
        grandparent: Option<&[u8]>,
        attributes: Attributes<'_>,
    ) -> Result<Option<Target>, SiprecError> {
        Ok(match (depth, parent, name) {
            (3, b"group", b"associate-time") => Some(Target::GroupAssociate),
            (3, b"group", b"disassociate-time") => Some(Target::GroupDisassociate),
            (3, b"session", b"sipSessionID") => Some(Target::SipSessionId),
            (3, b"session", b"group-ref") => Some(Target::GroupRef),
            (3, b"session", b"start-time") => Some(Target::StartTime),
            (3, b"session", b"end-time") => Some(Target::EndTime),
            (3, b"stream", b"label") => Some(Target::Label),
            (3, b"sessionrecordingassoc", b"associate-time") => Some(Target::RecordingAssociate),
            (3, b"sessionrecordingassoc", b"disassociate-time") => {
                Some(Target::RecordingDisassociate)
            }
            (3, b"participantsessionassoc", b"associate-time") => {
                Some(Target::ParticipantAssociate)
            }
            (3, b"participantsessionassoc", b"disassociate-time") => {
                Some(Target::ParticipantDisassociate)
            }
            (3, b"participantstreamassoc", b"send") => Some(Target::Send),
            (3, b"participantstreamassoc", b"recv") => Some(Target::Recv),
            (3, b"participant", b"nameID") => {
                let aor = attributes
                    .text("aor")?
                    .map(String::from)
                    .ok_or(SiprecError::MissingAttribute("aor"))?;
                if let Some(participant) = self.metadata.participants.last_mut() {
                    participant.name_ids.push(NameId {
                        aor,
                        names: Vec::new(),
                    });
                }
                self.count()?;
                None
            }
            (4, b"nameID", b"name") if grandparent == Some(b"participant") => {
                let lang = attributes.text("lang")?.map(String::from);
                if let Some(name_id) = self
                    .metadata
                    .participants
                    .last_mut()
                    .and_then(|p| p.name_ids.last_mut())
                {
                    name_id.names.push(Name {
                        lang,
                        text: String::new(),
                    });
                }
                self.count()?;
                Some(Target::Name)
            }
            _ => None,
        })
    }

    fn close(&mut self, depth: usize) -> Result<(), SiprecError> {
        let Some((target, at)) = self.target else {
            return Ok(());
        };
        if at != depth {
            return Ok(());
        }
        self.target = None;
        let text = self.text.trim().to_owned();
        let m = &mut self.metadata;
        match target {
            Target::DataMode => {
                m.data_mode = if text.eq_ignore_ascii_case("complete") {
                    DataMode::Complete
                } else if text.eq_ignore_ascii_case("partial") {
                    DataMode::Partial
                } else {
                    return Err(SiprecError::Malformed("datamode"));
                };
            }
            Target::GroupAssociate => set(m.groups.last_mut().map(|g| &mut g.associate_time), text),
            Target::GroupDisassociate => {
                set(m.groups.last_mut().map(|g| &mut g.disassociate_time), text);
            }
            Target::SipSessionId => {
                if let Some(s) = m.sessions.last_mut() {
                    s.sip_session_ids.push(text);
                }
            }
            Target::GroupRef => set(m.sessions.last_mut().map(|s| &mut s.group_ref), text),
            Target::StartTime => set(m.sessions.last_mut().map(|s| &mut s.start_time), text),
            Target::EndTime => set(m.sessions.last_mut().map(|s| &mut s.end_time), text),
            Target::Label => set(m.streams.last_mut().map(|s| &mut s.label), text),
            Target::RecordingAssociate => set(
                m.session_recording
                    .last_mut()
                    .map(|a| &mut a.associate_time),
                text,
            ),
            Target::RecordingDisassociate => set(
                m.session_recording
                    .last_mut()
                    .map(|a| &mut a.disassociate_time),
                text,
            ),
            Target::ParticipantAssociate => set(
                m.participant_sessions
                    .last_mut()
                    .map(|a| &mut a.associate_time),
                text,
            ),
            Target::ParticipantDisassociate => set(
                m.participant_sessions
                    .last_mut()
                    .map(|a| &mut a.disassociate_time),
                text,
            ),
            Target::Send | Target::Recv => {
                if let Some(a) = m.participant_streams.last_mut() {
                    if a.send.len() + a.recv.len() >= MAX_ITEMS {
                        return Err(SiprecError::TooLarge("stream references"));
                    }
                    if target == Target::Send {
                        a.send.push(text);
                    } else {
                        a.recv.push(text);
                    }
                }
            }
            Target::Name => {
                if let Some(name) = m
                    .participants
                    .last_mut()
                    .and_then(|p| p.name_ids.last_mut())
                    .and_then(|n| n.names.last_mut())
                {
                    name.text = text;
                }
            }
        }
        Ok(())
    }
}

fn set(slot: Option<&mut Option<String>>, text: String) {
    if let Some(slot) = slot {
        *slot = Some(text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sipral_core::msg::{MediaTypeRef, Multipart, ParseMode, ParseScratch, parse};

    /// RFC 7865 §8.1's complete metadata example as the RFC prints it, less
    /// the three columns of page indentation and with its two carrier
    /// domains moved under `example.com`, the only change.
    const RFC_7865_EXAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
  <recording xmlns='urn:ietf:params:xml:ns:recording:1'>
  <datamode>complete</datamode>
  <group group_id="7+OTCyoxTmqmqyA/1weDAg==">
    <associate-time>2010-12-16T23:41:07Z</associate-time>
    <!-- Standardized extension -->
    <call-center xmlns='urn:ietf:params:xml:ns:callcenter'>
          <supervisor>sip:alice@atlanta.example.com</supervisor>
    </call-center>
    <mydata xmlns='http://example.com/my'>
          <structure>FOO!</structure>
          <whatever>bar</whatever>
    </mydata>
  </group>
  <session session_id="hVpd7YQgRW2nD22h7q60JQ==">
        <sipSessionID>ab30317f1a784dc48ff824d0d3715d86;
        remote=47755a9de7794ba387653f2099600ef2</sipSessionID>
        <group-ref>7+OTCyoxTmqmqyA/1weDAg==</group-ref>
        <!-- Standardized extension -->
    <mydata xmlns='http://example.com/my'>
          <structure>FOO!</structure>
           <whatever>bar</whatever>
        </mydata>
  </session>
  <participant participant_id="srfBElmCRp2QB23b7Mpk0w==">
        <nameID aor="sip:bob@biloxi.example.com">
           <name xml:lang="it">Bob</name>
        </nameID>
        <!-- Standardized extension -->
        <mydata xmlns='http://example.com/my'>
                <structure>FOO!</structure>
                <whatever>bar</whatever>
        </mydata>
  </participant>
  <participant participant_id="zSfPoSvdSDCmU3A3TRDxAw==">
        <nameID aor="sip:Paul@biloxi.example.com">
          <name xml:lang="it">Paul</name>
        </nameID>
        <!-- Standardized extension -->
        <mydata xmlns='http://example.com/my'>
           <structure>FOO!</structure>
           <whatever>bar</whatever>
        </mydata>
  </participant>
  <stream stream_id="UAAMm5GRQKSCMVvLyl4rFw=="
          session_id="hVpd7YQgRW2nD22h7q60JQ==">
        <label>96</label>
  </stream>
  <stream stream_id="i1Pz3to5hGk8fuXl+PbwCw=="
           session_id="hVpd7YQgRW2nD22h7q60JQ==">
         <label>97</label>
  </stream>
  <stream stream_id="8zc6e0lYTlWIINA6GR+3ag=="
           session_id="hVpd7YQgRW2nD22h7q60JQ==">
        <label>98</label>
  </stream>
  <stream stream_id="EiXGlc+4TruqqoDaNE76ag=="
           session_id="hVpd7YQgRW2nD22h7q60JQ==">
        <label>99</label>
  </stream>
  <sessionrecordingassoc session_id="hVpd7YQgRW2nD22h7q60JQ==">
                <associate-time>2010-12-16T23:41:07Z</associate-time>
  </sessionrecordingassoc>
  <participantsessionassoc
       participant_id="srfBElmCRp2QB23b7Mpk0w=="
       session_id="hVpd7YQgRW2nD22h7q60JQ==">
        <associate-time>2010-12-16T23:41:07Z</associate-time>
  </participantsessionassoc>
  <participantsessionassoc
       participant_id="zSfPoSvdSDCmU3A3TRDxAw=="
       session_id="hVpd7YQgRW2nD22h7q60JQ==">
           <associate-time>2010-12-16T23:41:07Z</associate-time>
  </participantsessionassoc>
  <participantstreamassoc
       participant_id="srfBElmCRp2QB23b7Mpk0w==">
           <send>i1Pz3to5hGk8fuXl+PbwCw==</send>
           <send>UAAMm5GRQKSCMVvLyl4rFw==</send>
           <recv>8zc6e0lYTlWIINA6GR+3ag==</recv>
           <recv>EiXGlc+4TruqqoDaNE76ag==</recv>
  </participantstreamassoc>
  <participantstreamassoc
       participant_id="zSfPoSvdSDCmU3A3TRDxAw==">
           <send>8zc6e0lYTlWIINA6GR+3ag==</send>
           <send>EiXGlc+4TruqqoDaNE76ag==</send>
           <recv>UAAMm5GRQKSCMVvLyl4rFw==</recv>
           <recv>i1Pz3to5hGk8fuXl+PbwCw==</recv>
  </participantstreamassoc>
</recording>
"#;

    /// A two-stream variant of RFC 7865 §8.1's example, extension data and
    /// comments included: a group, one session, two participants each
    /// sending one of two labelled streams, and every association.
    const RFC_EXAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<recording xmlns='urn:ietf:params:xml:ns:recording:1'>
  <datamode>complete</datamode>
  <group group_id="7+OTCyoxTmqmqyA/1weDAg==">
    <associate-time>2010-12-16T23:41:07Z</associate-time>
    <!-- Standardized extension -->
    <call-center xmlns='urn:ietf:params:xml:ns:callcenter'>
      <supervisor>sip:alice@atlanta.example.com</supervisor>
    </call-center>
    <mydata xmlns='http://example.com/my'>
      <structure>structure!</structure>
      <whatever>structure</whatever>
    </mydata>
  </group>
  <session session_id="hVpd7YQgRW2nD22h7q60JQ==">
    <sipSessionID>ab30317f1a784dc48ff824d0d3715d86;
      remote=47755a9de7794ba387653f2099600ef2</sipSessionID>
    <group-ref>7+OTCyoxTmqmqyA/1weDAg==</group-ref>
    <!-- Standardized extension -->
    <mydata xmlns='http://example.com/my'>
      <structure>FOO!</structure>
      <whatever>bar</whatever>
    </mydata>
  </session>
  <participant participant_id="srfBElmCRp2QB23b7Mpk0w==">
    <nameID aor="sip:alice@atlanta.example.com">
      <name xml:lang="it">Alice</name>
    </nameID>
    <!-- Standardized extension -->
    <mydata xmlns='http://example.com/my'>
      <structure>FOO!</structure>
      <whatever>bar</whatever>
    </mydata>
  </participant>
  <participant participant_id="zSfPoSvdSDCmU3A3TRDxAw==">
    <nameID aor="sip:bob@biloxi.example.com">
      <name xml:lang="it">Bob</name>
    </nameID>
    <!-- Standardized extension -->
    <mydata xmlns='http://example.com/my'>
      <structure>FOO!</structure>
      <whatever>bar</whatever>
    </mydata>
  </participant>
  <stream stream_id="UAAMm5GRQKSCMVvLyl4rFw=="
      session_id="hVpd7YQgRW2nD22h7q60JQ==">
    <label>96</label>
  </stream>
  <stream stream_id="i1Pz3to5hGk8fuXl+PbwCw=="
      session_id="hVpd7YQgRW2nD22h7q60JQ==">
    <label>97</label>
  </stream>
  <sessionrecordingassoc session_id="hVpd7YQgRW2nD22h7q60JQ==">
    <associate-time>2010-12-16T23:41:07Z</associate-time>
  </sessionrecordingassoc>
  <participantsessionassoc
      participant_id="srfBElmCRp2QB23b7Mpk0w=="
      session_id="hVpd7YQgRW2nD22h7q60JQ==">
    <associate-time>2010-12-16T23:41:07Z</associate-time>
  </participantsessionassoc>
  <participantsessionassoc
      participant_id="zSfPoSvdSDCmU3A3TRDxAw=="
      session_id="hVpd7YQgRW2nD22h7q60JQ==">
    <associate-time>2010-12-16T23:41:07Z</associate-time>
  </participantsessionassoc>
  <participantstreamassoc
      participant_id="srfBElmCRp2QB23b7Mpk0w==">
    <send>i1Pz3to5hGk8fuXl+PbwCw==</send>
    <recv>UAAMm5GRQKSCMVvLyl4rFw==</recv>
  </participantstreamassoc>
  <participantstreamassoc
      participant_id="zSfPoSvdSDCmU3A3TRDxAw==">
    <send>UAAMm5GRQKSCMVvLyl4rFw==</send>
    <recv>i1Pz3to5hGk8fuXl+PbwCw==</recv>
  </participantstreamassoc>
</recording>
"#;

    const SESSION: &str = "hVpd7YQgRW2nD22h7q60JQ==";
    const ALICE: &str = "srfBElmCRp2QB23b7Mpk0w==";
    const BOB: &str = "zSfPoSvdSDCmU3A3TRDxAw==";
    const STREAM_96: &str = "UAAMm5GRQKSCMVvLyl4rFw==";
    const STREAM_97: &str = "i1Pz3to5hGk8fuXl+PbwCw==";

    fn call() -> RecordedCall {
        RecordedCall {
            session_id: SESSION.into(),
            sip_session_id: Some("ab30317f1a784dc48ff824d0d3715d86".into()),
            group_id: Some("7+OTCyoxTmqmqyA/1weDAg==".into()),
            started: Some("2010-12-16T23:41:07Z".into()),
            parties: vec![
                RecordedParty {
                    id: ALICE.into(),
                    aor: "sip:alice@atlanta.example.com".into(),
                    name: Some("Alice".into()),
                    sends: vec![RecordedStream {
                        id: STREAM_97.into(),
                        label: "97".into(),
                    }],
                },
                RecordedParty {
                    id: BOB.into(),
                    aor: "sip:bob@biloxi.example.com".into(),
                    name: Some("Bob".into()),
                    sends: vec![RecordedStream {
                        id: STREAM_96.into(),
                        label: "96".into(),
                    }],
                },
            ],
        }
    }

    #[test]
    fn the_rfcs_example_reads_as_the_rfc_describes_it() {
        let m = RecordingMetadata::parse(RFC_EXAMPLE.as_bytes()).expect("the example");
        assert_eq!(m.data_mode, DataMode::Complete);
        let [group] = m.groups.as_slice() else {
            panic!("one group");
        };
        assert_eq!(
            group.associate_time.as_deref(),
            Some("2010-12-16T23:41:07Z")
        );
        let [session] = m.sessions.as_slice() else {
            panic!("one session");
        };
        assert_eq!(session.id, SESSION);
        assert_eq!(session.group_ref.as_deref(), Some(group.id.as_str()));
        assert_eq!(
            session.sip_session_ids,
            ["ab30317f1a784dc48ff824d0d3715d86;\n      remote=47755a9de7794ba387653f2099600ef2"]
        );
        let names: Vec<(&str, &str, Option<&str>)> = m
            .participants
            .iter()
            .flat_map(|p| &p.name_ids)
            .flat_map(|n| n.names.iter().map(move |name| (n.aor.as_str(), name)))
            .map(|(aor, name)| (aor, name.text.as_str(), name.lang.as_deref()))
            .collect();
        assert_eq!(
            names,
            [
                ("sip:alice@atlanta.example.com", "Alice", Some("it")),
                ("sip:bob@biloxi.example.com", "Bob", Some("it"))
            ]
        );
        let labels: Vec<Option<&str>> = m.streams.iter().map(|s| s.label.as_deref()).collect();
        assert_eq!(labels, [Some("96"), Some("97")]);
        assert_eq!(m.session_recording.len(), 1);
        assert_eq!(m.participant_sessions.len(), 2);
        let alice = m
            .participant_streams
            .iter()
            .find(|a| a.participant_id == ALICE)
            .expect("alice");
        assert_eq!(alice.send, [STREAM_97]);
        assert_eq!(alice.recv, [STREAM_96]);
        m.validate().expect("every reference resolves");
    }

    #[test]
    fn rfc_7865s_own_example_reads_as_it_describes_it() {
        let m = RecordingMetadata::parse(RFC_7865_EXAMPLE.as_bytes()).expect("the example");
        assert_eq!(m.data_mode, DataMode::Complete);
        assert_eq!(m.groups.len(), 1);
        assert_eq!(m.sessions.len(), 1);
        let names: Vec<(&str, &str)> = m
            .participants
            .iter()
            .flat_map(|p| &p.name_ids)
            .flat_map(|n| {
                n.names
                    .iter()
                    .map(move |name| (n.aor.as_str(), name.text.as_str()))
            })
            .collect();
        assert_eq!(
            names,
            [
                ("sip:bob@biloxi.example.com", "Bob"),
                ("sip:Paul@biloxi.example.com", "Paul")
            ]
        );
        let labels: Vec<Option<&str>> = m.streams.iter().map(|s| s.label.as_deref()).collect();
        assert_eq!(labels, [Some("96"), Some("97"), Some("98"), Some("99")]);
        let bob = m
            .participant_streams
            .iter()
            .find(|a| a.participant_id == ALICE)
            .expect("the first participant");
        assert_eq!(bob.send, [STREAM_97, STREAM_96]);
        assert_eq!(
            bob.recv,
            ["8zc6e0lYTlWIINA6GR+3ag==", "EiXGlc+4TruqqoDaNE76ag=="]
        );
        m.validate().expect("every reference resolves");
    }

    #[test]
    fn a_recorded_call_builds_the_metadata_the_rfc_shows() {
        let built = call().metadata();
        let mut expected = RecordingMetadata::parse(RFC_EXAMPLE.as_bytes()).expect("parsed");
        // the example's Session-ID also carries the far end's half, and its
        // streams are listed by label; neither changes what is described
        expected.sessions[0].sip_session_ids = vec!["ab30317f1a784dc48ff824d0d3715d86".into()];
        expected.streams.reverse();
        for p in &mut expected.participants {
            for n in &mut p.name_ids {
                for name in &mut n.names {
                    name.lang = None;
                }
            }
        }
        assert_eq!(built, expected);
    }

    #[test]
    fn what_is_written_reads_back_the_same() {
        let mut m = call().metadata();
        m.sessions[0].start_time = Some("2010-12-16T23:41:07Z".into());
        m.participants[0].name_ids[0].names.push(Name {
            lang: Some("en".into()),
            text: "Alice <& \"Co\">".into(),
        });
        m.participant_sessions[1].disassociate_time = Some("2010-12-16T23:50:00Z".into());
        let xml = m.to_xml().expect("written");
        assert!(xml.contains("<recording xmlns=\"urn:ietf:params:xml:ns:recording:1\">"));
        assert!(xml.contains("<datamode>complete</datamode>"));
        assert!(xml.contains("<name xml:lang=\"en\">Alice &lt;&amp; &quot;Co&quot;&gt;</name>"));
        assert_eq!(RecordingMetadata::parse(xml.as_bytes()).expect("read"), m);
    }

    #[test]
    fn partial_metadata_carries_only_the_change() {
        let mut m = RecordingMetadata::new(DataMode::Partial);
        m.participant_sessions.push(ParticipantSessionAssoc {
            participant_id: BOB.into(),
            session_id: SESSION.into(),
            associate_time: None,
            disassociate_time: Some("2010-12-16T23:50:00Z".into()),
        });
        let xml = m
            .to_xml()
            .expect("a partial document names what it does not hold");
        assert!(xml.contains("<datamode>partial</datamode>"));
        assert_eq!(RecordingMetadata::parse(xml.as_bytes()).expect("read"), m);
    }

    #[test]
    fn a_complete_document_refers_only_to_what_it_holds() {
        let mut m = call().metadata();
        m.participant_streams[0].send.push("nowhere".into());
        assert_eq!(
            m.to_xml(),
            Err(SiprecError::UnknownReference(
                "participantstreamassoc stream"
            ))
        );
        let mut m = call().metadata();
        m.streams[0].session_id = "other".into();
        assert_eq!(
            m.validate(),
            Err(SiprecError::UnknownReference("stream session_id"))
        );
        let mut m = call().metadata();
        m.sessions[0].group_ref = Some("other".into());
        assert_eq!(
            m.validate(),
            Err(SiprecError::UnknownReference("group-ref"))
        );
        let mut m = call().metadata();
        m.participant_sessions[0].participant_id = "other".into();
        assert_eq!(
            m.validate(),
            Err(SiprecError::UnknownReference("participantsessionassoc"))
        );
    }

    #[test]
    fn every_association_resolves_in_a_complete_document() {
        let mut m = call().metadata();
        m.session_recording[0].session_id = "other".into();
        assert_eq!(
            m.validate(),
            Err(SiprecError::UnknownReference("sessionrecordingassoc"))
        );
        let mut m = call().metadata();
        m.participant_sessions[0].session_id = "other".into();
        assert_eq!(
            m.validate(),
            Err(SiprecError::UnknownReference("participantsessionassoc"))
        );
        let mut m = call().metadata();
        m.participant_streams[0].participant_id = "other".into();
        assert_eq!(
            m.validate(),
            Err(SiprecError::UnknownReference("participantstreamassoc"))
        );
    }

    #[test]
    fn a_value_xml_cannot_carry_is_refused() {
        let mut m = call().metadata();
        m.participants[0].id = String::new();
        m.participant_sessions.clear();
        m.participant_streams.clear();
        assert_eq!(
            m.to_xml(),
            Err(SiprecError::IllegalValue("an empty attribute"))
        );
        let mut m = call().metadata();
        m.participants[0].name_ids[0].names[0].text = "a\u{1}b".into();
        assert_eq!(
            m.to_xml(),
            Err(SiprecError::IllegalValue("a control character"))
        );
    }

    #[test]
    fn whitespace_a_reader_would_normalise_is_written_as_a_reference() {
        // XML 1.0 §2.11 turns CR LF and a lone CR into LF before anything
        // else sees them, and §3.3.3 turns TAB, LF and CR in an attribute
        // value into spaces: only a character reference survives either
        let mut m = call().metadata();
        m.participants[0].name_ids[0].names[0].text = "one\r\ntwo\rthree\tfour\nfive".into();
        m.participants[0].name_ids[0].aor = "sip:a\tb\nc\rd@example.com".into();
        let xml = m.to_xml().expect("written");
        assert!(xml.contains("<name>one&#13;\ntwo&#13;three\tfour\nfive</name>"));
        assert!(xml.contains("aor=\"sip:a&#9;b&#10;c&#13;d@example.com\""));
        assert_eq!(RecordingMetadata::parse(xml.as_bytes()).expect("read"), m);
    }

    #[test]
    fn a_value_is_bounded_as_written_not_as_given() {
        // 300 characters, each written as five: past what the reader takes
        let mut m = call().metadata();
        m.participants[0].name_ids[0].names[0].text = "&".repeat(300);
        assert_eq!(
            m.to_xml(),
            Err(SiprecError::IllegalValue("a value too long to read back"))
        );
        let mut m = call().metadata();
        m.participants[0].name_ids[0].aor = format!("sip:{}@example.com", "\"".repeat(300));
        assert_eq!(
            m.to_xml(),
            Err(SiprecError::IllegalValue("a value too long to read back"))
        );
        // and whatever is written, however escaped, reads back
        let mut m = call().metadata();
        m.participants[0].name_ids[0].names[0].text = format!("{}x", "&".repeat(203));
        let xml = m.to_xml().expect("1 016 bytes written");
        assert_eq!(RecordingMetadata::parse(xml.as_bytes()).expect("read"), m);
    }

    #[test]
    fn a_noncharacter_xml_excludes_is_refused() {
        // XML 1.0 §2.2: Char stops at #xFFFD, so #xFFFE and #xFFFF are not
        // characters a document may hold
        for bad in ["a\u{FFFE}b", "a\u{FFFF}b"] {
            let mut m = call().metadata();
            m.participants[0].name_ids[0].names[0].text = bad.into();
            assert_eq!(
                m.to_xml(),
                Err(SiprecError::IllegalValue("a character XML excludes"))
            );
        }
        let mut m = call().metadata();
        m.participants[0].name_ids[0].names[0].text = "a\u{FFFD}\u{10000}b".into();
        assert!(m.to_xml().is_ok());
    }

    #[test]
    fn labels_are_checked_against_the_sdp() {
        let sdp = b"v=0\r\n\
o=- 1 1 IN IP4 192.0.2.1\r\n\
s=-\r\n\
c=IN IP4 192.0.2.1\r\n\
t=0 0\r\n\
m=audio 49170 RTP/AVP 0\r\n\
a=label:96\r\n\
a=sendonly\r\n\
m=audio 49172 RTP/AVP 0\r\n\
a=label:97\r\n\
a=sendonly\r\n";
        let sdp = sipral_core::sdp::parse(sdp).expect("sdp");
        let m = call().metadata();
        assert_eq!(m.check_labels(&sdp), Ok(()));
        let mut unknown = m;
        unknown.streams[0].label = Some("98".into());
        assert_eq!(unknown.check_labels(&sdp), Err(SiprecError::UnknownLabel));
    }

    #[test]
    fn the_reader_refuses_what_is_not_recording_metadata() {
        assert_eq!(
            RecordingMetadata::parse(b"<dialog-info/>"),
            Err(SiprecError::NotRecording)
        );
        assert_eq!(
            RecordingMetadata::parse(b"<recording xmlns='urn:example:other'/>"),
            Err(SiprecError::NotRecording)
        );
        assert_eq!(
            RecordingMetadata::parse(b""),
            Err(SiprecError::NotRecording)
        );
        assert!(
            RecordingMetadata::parse(
                b"<rs:recording xmlns:rs='urn:ietf:params:xml:ns:recording:1'/>"
            )
            .is_ok()
        );
        assert_eq!(
            RecordingMetadata::parse(b"<recording><datamode>sometimes</datamode></recording>"),
            Err(SiprecError::Malformed("datamode"))
        );
        assert_eq!(
            RecordingMetadata::parse(b"<recording><session/></recording>"),
            Err(SiprecError::MissingAttribute("session_id"))
        );
        assert_eq!(
            RecordingMetadata::parse(b"<recording></recording><recording/>"),
            Err(SiprecError::Malformed("a second root element"))
        );
        assert_eq!(
            RecordingMetadata::parse(b"<recording><group group_id='a'></recording>"),
            Err(SiprecError::Malformed("closing tag does not match"))
        );
        assert_eq!(
            RecordingMetadata::parse(b"<!DOCTYPE r [<!ENTITY x 'y'>]><recording>&x;</recording>"),
            Err(SiprecError::Refused("a declaration or CDATA section"))
        );
        assert_eq!(
            RecordingMetadata::parse(b"<recording><datamode>complete"),
            Err(SiprecError::Malformed("an element never closed"))
        );
    }

    #[test]
    fn the_reader_is_bounded() {
        let deep = format!("<recording>{}", "<x>".repeat(MAX_DEPTH));
        assert_eq!(
            RecordingMetadata::parse(deep.as_bytes()),
            Err(SiprecError::TooLarge("nesting"))
        );
        let many = format!(
            "<recording>{}</recording>",
            "<group group_id='g'/>".repeat(MAX_ITEMS + 1)
        );
        assert_eq!(
            RecordingMetadata::parse(many.as_bytes()),
            Err(SiprecError::TooLarge("item count"))
        );
        let elements = format!("<recording>{}</recording>", "<x/>".repeat(MAX_ELEMENTS));
        assert_eq!(
            RecordingMetadata::parse(elements.as_bytes()),
            Err(SiprecError::TooLarge("element count"))
        );
        let huge = vec![b' '; MAX_BYTES + 1];
        assert_eq!(
            RecordingMetadata::parse(&huge),
            Err(SiprecError::TooLarge("document"))
        );
        let long = format!(
            "<recording><session session_id='s'><group-ref>{0}<!---->{0}</group-ref>\
</session></recording>",
            "a".repeat(MAX_TEXT / 2 + 1)
        );
        assert_eq!(
            RecordingMetadata::parse(long.as_bytes()),
            Err(SiprecError::TooLarge("text"))
        );
    }

    #[test]
    fn the_stream_references_of_one_association_are_bounded() {
        let xml = format!(
            "<recording><participantstreamassoc participant_id='p'>{}\
</participantstreamassoc></recording>",
            "<send>s</send>".repeat(MAX_ITEMS + 1)
        );
        assert_eq!(
            RecordingMetadata::parse(xml.as_bytes()),
            Err(SiprecError::TooLarge("stream references"))
        );
    }

    #[test]
    fn a_name_id_needs_its_aor_and_a_name_needs_a_participant() {
        assert_eq!(
            RecordingMetadata::parse(
                b"<recording><participant participant_id='p'><nameID/></participant></recording>"
            ),
            Err(SiprecError::MissingAttribute("aor"))
        );
        // a nameID in a session is an extension, and its name is nobody's
        let xml = b"<recording><participant participant_id='p'>\
<nameID aor='sip:a@example.com'><name>Alice</name></nameID></participant>\
<session session_id='s'><nameID aor='sip:m@example.com'><name>Mallory</name></nameID>\
</session></recording>";
        let m = RecordingMetadata::parse(xml).expect("read");
        let names: Vec<&str> = m.participants[0].name_ids[0]
            .names
            .iter()
            .map(|n| n.text.as_str())
            .collect();
        assert_eq!(names, ["Alice"]);
    }

    #[test]
    fn extension_elements_do_not_leak_into_known_ones() {
        let xml = b"<recording><stream stream_id='s' session_id='x'>\
<ext><label>not this</label></ext><label><ext>nor this</ext>96</label></stream></recording>";
        let m = RecordingMetadata::parse(xml).expect("read");
        assert_eq!(m.streams[0].label.as_deref(), Some("96"));
    }

    #[test]
    fn ids_are_base64_as_rfc_4648_writes_it() {
        // RFC 4648 §10
        for (input, output) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(input.as_bytes()), output);
        }
        let id = metadata_id([0xff; 16]);
        assert_eq!(id, "/////////////////////w==");
    }

    #[test]
    fn the_invite_body_is_the_sdp_then_the_metadata() {
        let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n";
        let metadata = call().metadata();
        let built = recording_session_body(sdp, &metadata).expect("built");
        let ct = MediaTypeRef::parse(built.content_type().as_bytes()).expect("a type");
        assert!(ct.is("multipart", "mixed"));
        let body = Multipart::parse(&ct, built.body()).expect("reads back");
        let [first, second] = body.parts() else {
            panic!("two parts");
        };
        assert!(first.is("application", "sdp"));
        assert_eq!(first.body(), sdp);
        assert!(second.is("application", "rs-metadata+xml"));
        assert!(
            second
                .disposition()
                .is_some_and(|d| d.is("recording-session"))
        );
        assert_eq!(
            RecordingMetadata::parse(second.body()).expect("metadata"),
            metadata
        );
    }

    fn invite(extra: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "INVITE sip:srs@example.com SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds\r\n\
Max-Forwards: 70\r\n\
To: <sip:srs@example.com>\r\n\
From: <sip:src@example.com>;tag=1928301774\r\n\
Call-ID: a84b4c76e66710@192.0.2.1\r\n\
CSeq: 314159 INVITE\r\n\
{extra}\
Content-Type: {content_type}\r\n\
Content-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn a_recording_invite_is_recognised_and_its_offer_read() {
        let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n";
        let metadata = call().metadata();
        let built = recording_session_body(sdp, &metadata).expect("built");
        let contact = with_src_feature_tag("<sip:src@192.0.2.1:5060>");
        assert_eq!(contact, "<sip:src@192.0.2.1:5060>;+sip.src");
        assert_eq!(with_src_feature_tag(&contact), contact);
        let bytes = invite(
            &format!("Contact: {contact}\r\nRequire: {OPTION_TAG}\r\nSupported: timer, siprec\r\n"),
            built.content_type(),
            built.body(),
        );
        let mut scratch = ParseScratch::default();
        let message = parse(&bytes, &mut scratch, ParseMode::Strict).expect("parses");
        assert!(requires_siprec(&message));
        assert!(supports_siprec(&message));
        assert!(contact_has_feature_tag(&message, SRC_FEATURE_TAG));
        assert!(!contact_has_feature_tag(&message, SRS_FEATURE_TAG));
        let offer = read_recording_offer(&message).expect("an offer");
        assert_eq!(offer.sdp, sdp);
        assert_eq!(offer.metadata, metadata);
    }

    #[test]
    fn metadata_typed_as_rfc_7866_writes_it_is_found_without_a_disposition() {
        // RFC 7866 §9 and its examples type the metadata
        // application/rs-metadata, RFC 7865 §5 application/rs-metadata+xml
        let sdp = b"v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n";
        let metadata = call().metadata();
        let xml = metadata.to_xml().expect("xml");
        for media in ["application/rs-metadata", "application/rs-metadata+xml"] {
            let built = MultipartBuilder::mixed()
                .part(Part::new("application/sdp", sdp))
                .part(Part::new(media, xml.as_bytes()))
                .build()
                .expect("built");
            let bytes = invite("", built.content_type(), built.body());
            let mut scratch = ParseScratch::default();
            let message = parse(&bytes, &mut scratch, ParseMode::Strict).expect("parses");
            let offer = read_recording_offer(&message).expect(media);
            assert_eq!(offer.metadata, metadata, "{media}");
        }
    }

    #[test]
    fn a_feature_tag_valued_false_is_not_the_feature() {
        // RFC 3840: a boolean feature tag is TRUE bare or written "TRUE",
        // and "FALSE" or "!TRUE" says the opposite
        for (contact, src) in [
            ("<sip:a@192.0.2.1>;+sip.src", true),
            ("<sip:a@192.0.2.1>;+SIP.SRC=\"TRUE\"", true),
            ("<sip:a@192.0.2.1>;+sip.src=\"!FALSE\"", true),
            ("<sip:a@192.0.2.1>;+sip.src=\"FALSE\"", false),
            ("<sip:a@192.0.2.1>;+sip.src=\"!TRUE\"", false),
            ("<sip:a@192.0.2.1>;+sip.srcx", false),
        ] {
            let bytes = invite(
                &format!("Contact: {contact}\r\n"),
                "application/sdp",
                b"v=0\r\n",
            );
            let mut scratch = ParseScratch::default();
            let message = parse(&bytes, &mut scratch, ParseMode::Strict).expect("parses");
            assert_eq!(
                contact_has_feature_tag(&message, SRC_FEATURE_TAG),
                src,
                "{contact}"
            );
        }
    }

    #[test]
    fn an_ordinary_invite_is_not_a_recording_session() {
        let sdp = b"v=0\r\n";
        let bytes = invite("Contact: <sip:a@192.0.2.1>\r\n", "application/sdp", sdp);
        let mut scratch = ParseScratch::default();
        let message = parse(&bytes, &mut scratch, ParseMode::Strict).expect("parses");
        assert!(!requires_siprec(&message));
        assert!(!supports_siprec(&message));
        assert!(!contact_has_feature_tag(&message, SRC_FEATURE_TAG));
        assert_eq!(
            read_recording_offer(&message).err(),
            Some(SiprecError::Multipart(MultipartError::NotMultipart))
        );
        let only_sdp = MultipartBuilder::mixed()
            .part(Part::new("application/sdp", sdp))
            .build()
            .expect("built");
        let bytes = invite("", only_sdp.content_type(), only_sdp.body());
        let message = parse(&bytes, &mut scratch, ParseMode::Strict).expect("parses");
        assert_eq!(
            read_recording_offer(&message).err(),
            Some(SiprecError::MissingPart(METADATA_CONTENT_TYPE))
        );
    }
}
