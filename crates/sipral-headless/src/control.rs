// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The control messages `docs/07-headless.md` names, and the frame kinds that
//! distinguish them on the wire.
//!
//! Audio shares the frame format but carries no JSON, so [`FrameKind::Audio`]
//! is here only to make the kind byte a closed set: every value a frame's
//! kind can legally hold is one variant of this enum, and nothing decodes a
//! byte outside it by guessing what was probably meant.
//!
//! Each message is a plain struct with public fields — there is no reason to
//! hide `call_id` behind an accessor — plus the JSON conversion `to_json_bytes`
//! and `decode` need, kept private because the shape of the JSON is this
//! module's business, not the caller's.

use core::fmt;

use crate::audio::{self, AudioConfig, AudioError, SampleRate};
use crate::json::{JsonError, Value};

/// What a frame's kind byte means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FrameKind {
    /// PCM, not JSON.
    Audio = 0,
    /// [`SessionOpen`].
    SessionOpen = 1,
    /// [`IncomingCall`].
    IncomingCall = 2,
    /// [`Answer`].
    Answer = 3,
    /// [`Reject`].
    Reject = 4,
    /// [`Hangup`].
    Hangup = 5,
    /// [`DtmfReceived`].
    DtmfReceived = 6,
    /// [`DtmfSend`].
    DtmfSend = 7,
    /// [`CallState`].
    CallState = 8,
    /// [`Transfer`].
    Transfer = 9,
    /// [`BargeIn`].
    BargeIn = 10,
    /// [`ErrorMessage`].
    Error = 11,
    /// [`VoiceActivity`].
    VoiceActivity = 12,
}

impl FrameKind {
    /// The byte this kind is written as.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for FrameKind {
    type Error = ControlError;

    fn try_from(byte: u8) -> Result<Self, ControlError> {
        Ok(match byte {
            0 => Self::Audio,
            1 => Self::SessionOpen,
            2 => Self::IncomingCall,
            3 => Self::Answer,
            4 => Self::Reject,
            5 => Self::Hangup,
            6 => Self::DtmfReceived,
            7 => Self::DtmfSend,
            8 => Self::CallState,
            9 => Self::Transfer,
            10 => Self::BargeIn,
            11 => Self::Error,
            12 => Self::VoiceActivity,
            other => return Err(ControlError::UnknownKind(other)),
        })
    }
}

/// One key of a DTMF keypad.
///
/// `0`-`9`, `*`, `#`, and `A`-`D`: the sixteen events RFC 4733 §7.1
/// registers, Table 7. `A` through `D` exist on very few real keypads, but
/// they are legal telephone-events and this crate has no basis to refuse
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DtmfDigit(char);

impl DtmfDigit {
    /// `None` for anything outside the sixteen-event alphabet.
    #[must_use]
    pub const fn new(digit: char) -> Option<Self> {
        match digit {
            '0'..='9' | '*' | '#' | 'A'..='D' => Some(Self(digit)),
            _ => None,
        }
    }

    /// The digit itself.
    #[must_use]
    pub const fn get(self) -> char {
        self.0
    }
}

/// Parameters for opening a session: the sample rate and the frame duration
/// both directions of audio use for the socket's whole lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionOpen {
    /// The rate every audio frame is sampled at.
    pub sample_rate: SampleRate,
    /// How much audio one frame carries, in milliseconds.
    pub frame_duration_ms: u32,
}

impl SessionOpen {
    /// `sample_rate` at the document's default of twenty milliseconds.
    #[must_use]
    pub const fn new(sample_rate: SampleRate) -> Self {
        Self {
            sample_rate,
            frame_duration_ms: audio::DEFAULT_FRAME_DURATION_MS,
        }
    }

    /// The audio every frame of the session carries.
    ///
    /// # Errors
    /// Whatever [`AudioConfig::with_frame_duration_ms`] refuses: a duration
    /// of zero, or one too long for a frame's sixteen-bit length at this
    /// rate. A message decoded off the wire never holds either, since
    /// decoding refuses them; one built by hand can.
    pub fn audio(self) -> Result<AudioConfig, AudioError> {
        AudioConfig::with_frame_duration_ms(self.sample_rate, self.frame_duration_ms)
    }

    fn to_value(self) -> Result<Value, ControlError> {
        self.audio().map_err(ControlError::FrameDuration)?;
        Ok(Value::Object(vec![
            ("sample_rate".to_owned(), Value::from(self.sample_rate.hz())),
            (
                "frame_duration_ms".to_owned(),
                Value::from(self.frame_duration_ms),
            ),
        ]))
    }

    /// Checked here, where the message comes off the wire, rather than by
    /// whatever opens a session with it later: a session that cannot exist is
    /// the sender's mistake, and the error channel is where the sender hears
    /// about it (`docs/07-headless.md`).
    fn from_value(value: &Value) -> Result<Self, ControlError> {
        let hz = u32_field(value, "sample_rate")?;
        let sample_rate =
            SampleRate::try_from(hz).map_err(|_| ControlError::InvalidField("sample_rate"))?;
        let frame_duration_ms = optional_u32_field(value, "frame_duration_ms")?
            .unwrap_or(audio::DEFAULT_FRAME_DURATION_MS);
        let open = Self {
            sample_rate,
            frame_duration_ms,
        };
        open.audio().map_err(ControlError::FrameDuration)?;
        Ok(open)
    }
}

/// A call arriving, with who it is from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncomingCall {
    /// Identifies the call for every message about it from here on.
    pub call_id: String,
    /// The caller's address, such as a SIP or `tel:` URI.
    pub caller: String,
    /// The caller's display name, when one was offered.
    pub display_name: Option<String>,
}

impl IncomingCall {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("call_id".to_owned(), Value::from(self.call_id.as_str())),
            ("caller".to_owned(), Value::from(self.caller.as_str())),
            (
                "display_name".to_owned(),
                Value::from(self.display_name.as_deref()),
            ),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
            caller: string_field(value, "caller")?,
            display_name: optional_string_field(value, "display_name")?,
        })
    }
}

/// Answer the named call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The call to answer.
    pub call_id: String,
}

impl Answer {
    fn to_value(&self) -> Value {
        Value::Object(vec![(
            "call_id".to_owned(),
            Value::from(self.call_id.as_str()),
        )])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
        })
    }
}

/// Decline the named call before it is answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject {
    /// The call to decline.
    pub call_id: String,
    /// Why, for a log rather than for the caller — this crate does not touch
    /// SIP, so turning a reason into a status code is the wiring layer's
    /// decision.
    pub reason: Option<String>,
}

impl Reject {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("call_id".to_owned(), Value::from(self.call_id.as_str())),
            ("reason".to_owned(), Value::from(self.reason.as_deref())),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
            reason: optional_string_field(value, "reason")?,
        })
    }
}

/// End the named call, once it is up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hangup {
    /// The call to end.
    pub call_id: String,
    /// Why, for a log.
    pub reason: Option<String>,
}

impl Hangup {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("call_id".to_owned(), Value::from(self.call_id.as_str())),
            ("reason".to_owned(), Value::from(self.reason.as_deref())),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
            reason: optional_string_field(value, "reason")?,
        })
    }
}

/// A DTMF digit the caller sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DtmfReceived {
    /// Which call it arrived on.
    pub call_id: String,
    /// The digit.
    pub digit: DtmfDigit,
    /// How long it was held, when the source reported one.
    pub duration_ms: Option<u32>,
}

impl DtmfReceived {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("call_id".to_owned(), Value::from(self.call_id.as_str())),
            (
                "digit".to_owned(),
                Value::String(self.digit.get().to_string()),
            ),
            ("duration_ms".to_owned(), Value::from(self.duration_ms)),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
            digit: dtmf_field(value, "digit")?,
            duration_ms: optional_u32_field(value, "duration_ms")?,
        })
    }
}

/// Ask for a DTMF digit to be sent on the named call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DtmfSend {
    /// Which call to send it on.
    pub call_id: String,
    /// The digit.
    pub digit: DtmfDigit,
    /// How long to hold it, in milliseconds. `None` leaves the duration to
    /// whatever sends the tone.
    pub duration_ms: Option<u32>,
}

impl DtmfSend {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("call_id".to_owned(), Value::from(self.call_id.as_str())),
            (
                "digit".to_owned(),
                Value::String(self.digit.get().to_string()),
            ),
            ("duration_ms".to_owned(), Value::from(self.duration_ms)),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
            digit: dtmf_field(value, "digit")?,
            duration_ms: optional_u32_field(value, "duration_ms")?,
        })
    }
}

/// Where a call is in its lifecycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallStateKind {
    /// Placed, not yet answered.
    Ringing,
    /// Up, with audio flowing.
    Answered,
    /// Over.
    Ended {
        /// Why, for a log.
        reason: Option<String>,
    },
}

/// A call moved to a new state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallState {
    /// Which call.
    pub call_id: String,
    /// The state it moved to.
    pub state: CallStateKind,
}

impl CallState {
    fn to_value(&self) -> Value {
        let mut members = vec![("call_id".to_owned(), Value::from(self.call_id.as_str()))];
        match &self.state {
            CallStateKind::Ringing => members.push(("state".to_owned(), Value::from("ringing"))),
            CallStateKind::Answered => {
                members.push(("state".to_owned(), Value::from("answered")));
            }
            CallStateKind::Ended { reason } => {
                members.push(("state".to_owned(), Value::from("ended")));
                members.push(("reason".to_owned(), Value::from(reason.as_deref())));
            }
        }
        Value::Object(members)
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        let call_id = string_field(value, "call_id")?;
        let state = string_field(value, "state")?;
        let state = match state.as_str() {
            "ringing" => CallStateKind::Ringing,
            "answered" => CallStateKind::Answered,
            "ended" => CallStateKind::Ended {
                reason: optional_string_field(value, "reason")?,
            },
            _ => return Err(ControlError::InvalidField("state")),
        };
        Ok(Self { call_id, state })
    }
}

/// Transfer the named call to another destination.
///
/// Blind transfer only: the document does not describe an attended flow, and
/// one would need a second call to reference, which nothing here tracks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transfer {
    /// The call to transfer.
    pub call_id: String,
    /// Where to send it, such as a SIP or `tel:` URI.
    pub target: String,
}

impl Transfer {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("call_id".to_owned(), Value::from(self.call_id.as_str())),
            ("target".to_owned(), Value::from(self.target.as_str())),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
            target: string_field(value, "target")?,
        })
    }
}

/// Discard everything queued for playback on the named call, immediately.
///
/// This is the message the document's latency budget is measured against:
/// under 100 ms from here to silence on the wire. Nothing about that budget
/// is enforced by the type — it is a property of whatever reads this message
/// off the socket and acts on it, not of the message itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BargeIn {
    /// The call whose playback queue is discarded.
    pub call_id: String,
}

impl BargeIn {
    fn to_value(&self) -> Value {
        Value::Object(vec![(
            "call_id".to_owned(),
            Value::from(self.call_id.as_str()),
        )])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
        })
    }
}

/// The caller started or stopped talking, as this call's voice-activity
/// detector reads the audio decoded from it — not from anything the agent
/// sent. The signal an agent watches for barge-in: on `speaking: true` it
/// knows the caller has begun over whatever it is playing, and can answer
/// with [`BargeIn`] itself rather than waiting to be interrupted by silence
/// on its own microphone.
///
/// One message per transition, not one per frame: a caller that talks for
/// three seconds sends `speaking: true` once, at its first frame, and
/// `speaking: false` once, when the detector's hangover runs out — never a
/// message for every twenty milliseconds in between, which would turn one
/// sentence into a hundred and fifty of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoiceActivity {
    /// Which call.
    pub call_id: String,
    /// `true` from the frame the detector first read speech to the frame it
    /// reads a pause, `false` for the run in between.
    pub speaking: bool,
}

impl VoiceActivity {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("call_id".to_owned(), Value::from(self.call_id.as_str())),
            ("speaking".to_owned(), Value::Bool(self.speaking)),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: string_field(value, "call_id")?,
            speaking: bool_field(value, "speaking")?,
        })
    }
}

/// A code for [`ErrorMessage`] narrower than its free-text `message`.
///
/// Not from the document, which only says there is an error channel: this is
/// this crate's own small taxonomy, covering what the codec itself can
/// detect, plus `Other` for whatever the wiring layer reports that is none of
/// those.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    /// A frame or a control message did not follow the protocol.
    ProtocolViolation,
    /// A frame's declared length exceeded the session's maximum.
    FrameTooLarge,
    /// An audio frame was not exactly one frame at the session's size.
    InvalidAudioFrame,
    /// A message named a `call_id` this session has no call for.
    UnknownCall,
    /// A message arrived before session open.
    SessionNotOpen,
    /// Anything this taxonomy does not name.
    Internal,
    /// A code from outside this list, kept rather than collapsed into
    /// `Internal` so a caller that defined it still gets it back.
    /// [`OtherErrorCode`] cannot equal one of the six strings above, so
    /// nothing held here can be misread as one of them on the way back in.
    Other(OtherErrorCode),
}

impl ErrorCode {
    /// `code` as one of the six built-in variants, or `None` when it names
    /// none of them — the single place both [`ErrorCode::parse`] and
    /// [`OtherErrorCode::new`] check, so the two can never disagree about
    /// which strings are reserved.
    fn reserved(code: &str) -> Option<Self> {
        Some(match code {
            "protocol_violation" => Self::ProtocolViolation,
            "frame_too_large" => Self::FrameTooLarge,
            "invalid_audio_frame" => Self::InvalidAudioFrame,
            "unknown_call" => Self::UnknownCall,
            "session_not_open" => Self::SessionNotOpen,
            "internal" => Self::Internal,
            _ => return None,
        })
    }

    fn as_str(&self) -> &str {
        match self {
            Self::ProtocolViolation => "protocol_violation",
            Self::FrameTooLarge => "frame_too_large",
            Self::InvalidAudioFrame => "invalid_audio_frame",
            Self::UnknownCall => "unknown_call",
            Self::SessionNotOpen => "session_not_open",
            Self::Internal => "internal",
            Self::Other(code) => code.as_str(),
        }
    }

    fn parse(code: &str) -> Self {
        // `reserved` already turned away every string `OtherErrorCode::new`
        // would refuse, so building one straight from the leftover is safe.
        Self::reserved(code).unwrap_or_else(|| Self::Other(OtherErrorCode(code.to_owned())))
    }
}

/// A caller-defined [`ErrorCode`] outside this crate's own six.
///
/// Cannot equal one of them: on the wire a code is just its string, so a
/// value that collided would be read back as the reserved [`ErrorCode`]
/// instead of `Other`, changing identity with no error.
/// Refusing the collision here, at construction, is cheaper than teaching
/// the wire format to tell the two apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OtherErrorCode(String);

impl OtherErrorCode {
    /// `None` if `code` is one of [`ErrorCode`]'s six reserved strings.
    #[must_use]
    pub fn new(code: String) -> Option<Self> {
        if ErrorCode::reserved(&code).is_some() {
            None
        } else {
            Some(Self(code))
        }
    }

    /// The code text, exactly as given to [`OtherErrorCode::new`].
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Something went wrong, reported on the error channel rather than by
/// closing the socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorMessage {
    /// The call this concerns, when it concerns one rather than the session
    /// as a whole.
    pub call_id: Option<String>,
    /// A code a caller can match on.
    pub code: ErrorCode,
    /// A human-readable description.
    pub message: String,
}

impl ErrorMessage {
    fn to_value(&self) -> Value {
        Value::Object(vec![
            ("call_id".to_owned(), Value::from(self.call_id.as_deref())),
            ("code".to_owned(), Value::from(self.code.as_str())),
            ("message".to_owned(), Value::from(self.message.as_str())),
        ])
    }

    fn from_value(value: &Value) -> Result<Self, ControlError> {
        Ok(Self {
            call_id: optional_string_field(value, "call_id")?,
            code: ErrorCode::parse(&string_field(value, "code")?),
            message: string_field(value, "message")?,
        })
    }
}

/// Any control message this crate defines, tagged by the frame kind it
/// travels as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlMessage {
    /// [`SessionOpen`].
    SessionOpen(SessionOpen),
    /// [`IncomingCall`].
    IncomingCall(IncomingCall),
    /// [`Answer`].
    Answer(Answer),
    /// [`Reject`].
    Reject(Reject),
    /// [`Hangup`].
    Hangup(Hangup),
    /// [`DtmfReceived`].
    DtmfReceived(DtmfReceived),
    /// [`DtmfSend`].
    DtmfSend(DtmfSend),
    /// [`CallState`].
    CallState(CallState),
    /// [`Transfer`].
    Transfer(Transfer),
    /// [`BargeIn`].
    BargeIn(BargeIn),
    /// [`ErrorMessage`].
    Error(ErrorMessage),
    /// [`VoiceActivity`].
    VoiceActivity(VoiceActivity),
}

impl ControlMessage {
    /// The frame kind this message is written as.
    #[must_use]
    pub const fn kind(&self) -> FrameKind {
        match self {
            Self::SessionOpen(_) => FrameKind::SessionOpen,
            Self::IncomingCall(_) => FrameKind::IncomingCall,
            Self::Answer(_) => FrameKind::Answer,
            Self::Reject(_) => FrameKind::Reject,
            Self::Hangup(_) => FrameKind::Hangup,
            Self::DtmfReceived(_) => FrameKind::DtmfReceived,
            Self::DtmfSend(_) => FrameKind::DtmfSend,
            Self::CallState(_) => FrameKind::CallState,
            Self::Transfer(_) => FrameKind::Transfer,
            Self::BargeIn(_) => FrameKind::BargeIn,
            Self::Error(_) => FrameKind::Error,
            Self::VoiceActivity(_) => FrameKind::VoiceActivity,
        }
    }

    fn to_value(&self) -> Result<Value, ControlError> {
        Ok(match self {
            Self::SessionOpen(m) => m.to_value()?,
            Self::IncomingCall(m) => m.to_value(),
            Self::Answer(m) => m.to_value(),
            Self::Reject(m) => m.to_value(),
            Self::Hangup(m) => m.to_value(),
            Self::DtmfReceived(m) => m.to_value(),
            Self::DtmfSend(m) => m.to_value(),
            Self::CallState(m) => m.to_value(),
            Self::Transfer(m) => m.to_value(),
            Self::BargeIn(m) => m.to_value(),
            Self::Error(m) => m.to_value(),
            Self::VoiceActivity(m) => m.to_value(),
        })
    }

    /// The JSON payload this message's frame carries.
    ///
    /// # Errors
    /// [`ControlError::FrameDuration`] for a [`SessionOpen`] built by hand
    /// with a frame duration no session can have — refused on the way out as
    /// it would be on the way in, rather than written for the far end to
    /// refuse. [`JsonError::NumberOutOfRange`] otherwise, unreachable for a
    /// message built from this crate's own types since none of them can hold
    /// a non-finite number — but the writer's contract is honoured here
    /// rather than assumed.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, ControlError> {
        Ok(self.to_value()?.to_json_string()?.into_bytes())
    }

    /// Decode a control message from a frame's kind byte and JSON payload.
    ///
    /// # Errors
    /// [`ControlError::UnknownKind`] for a byte this crate does not define,
    /// [`ControlError::NotControl`] for [`FrameKind::Audio`], and whatever
    /// parsing the payload or reading its fields refused otherwise.
    pub fn decode(kind: u8, payload: &[u8]) -> Result<Self, ControlError> {
        let kind = FrameKind::try_from(kind)?;
        if kind == FrameKind::Audio {
            return Err(ControlError::NotControl(kind));
        }
        let value = crate::json::parse(payload)?;
        if !matches!(value, Value::Object(_)) {
            return Err(ControlError::NotAnObject);
        }
        Self::from_kind(kind, &value)
    }

    fn from_kind(kind: FrameKind, value: &Value) -> Result<Self, ControlError> {
        Ok(match kind {
            FrameKind::Audio => return Err(ControlError::NotControl(kind)),
            FrameKind::SessionOpen => Self::SessionOpen(SessionOpen::from_value(value)?),
            FrameKind::IncomingCall => Self::IncomingCall(IncomingCall::from_value(value)?),
            FrameKind::Answer => Self::Answer(Answer::from_value(value)?),
            FrameKind::Reject => Self::Reject(Reject::from_value(value)?),
            FrameKind::Hangup => Self::Hangup(Hangup::from_value(value)?),
            FrameKind::DtmfReceived => Self::DtmfReceived(DtmfReceived::from_value(value)?),
            FrameKind::DtmfSend => Self::DtmfSend(DtmfSend::from_value(value)?),
            FrameKind::CallState => Self::CallState(CallState::from_value(value)?),
            FrameKind::Transfer => Self::Transfer(Transfer::from_value(value)?),
            FrameKind::BargeIn => Self::BargeIn(BargeIn::from_value(value)?),
            FrameKind::Error => Self::Error(ErrorMessage::from_value(value)?),
            FrameKind::VoiceActivity => Self::VoiceActivity(VoiceActivity::from_value(value)?),
        })
    }
}

fn string_field(value: &Value, name: &'static str) -> Result<String, ControlError> {
    value
        .get(name)
        .ok_or(ControlError::MissingField(name))?
        .as_str()
        .map(str::to_owned)
        .ok_or(ControlError::InvalidField(name))
}

fn optional_string_field(
    value: &Value,
    name: &'static str,
) -> Result<Option<String>, ControlError> {
    match value.get(name) {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(v) => v
            .as_str()
            .map(|s| Some(s.to_owned()))
            .ok_or(ControlError::InvalidField(name)),
    }
}

fn u32_field(value: &Value, name: &'static str) -> Result<u32, ControlError> {
    let n = value
        .get(name)
        .ok_or(ControlError::MissingField(name))?
        .as_f64()
        .ok_or(ControlError::InvalidField(name))?;
    u32_from_number(n).ok_or(ControlError::InvalidField(name))
}

fn optional_u32_field(value: &Value, name: &'static str) -> Result<Option<u32>, ControlError> {
    match value.get(name) {
        None => Ok(None),
        Some(v) if v.is_null() => Ok(None),
        Some(v) => {
            let n = v.as_f64().ok_or(ControlError::InvalidField(name))?;
            u32_from_number(n)
                .map(Some)
                .ok_or(ControlError::InvalidField(name))
        }
    }
}

fn bool_field(value: &Value, name: &'static str) -> Result<bool, ControlError> {
    value
        .get(name)
        .ok_or(ControlError::MissingField(name))?
        .as_bool()
        .ok_or(ControlError::InvalidField(name))
}

fn dtmf_field(value: &Value, name: &'static str) -> Result<DtmfDigit, ControlError> {
    let s = value
        .get(name)
        .ok_or(ControlError::MissingField(name))?
        .as_str()
        .ok_or(ControlError::InvalidField(name))?;
    let mut chars = s.chars();
    let (Some(only), None) = (chars.next(), chars.next()) else {
        return Err(ControlError::InvalidField(name));
    };
    DtmfDigit::new(only).ok_or(ControlError::InvalidField(name))
}

/// A JSON number that is a non-negative whole number small enough for `u32`.
///
/// `f64` has no checked conversion to an integer type in `std`; the checks
/// above the cast make it exact rather than merely likely.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn u32_from_number(n: f64) -> Option<u32> {
    if n.is_finite() && n >= 0.0 && n.fract() == 0.0 && n <= f64::from(u32::MAX) {
        Some(n as u32)
    } else {
        None
    }
}

/// Why a control message could not be read or written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlError {
    /// A frame kind byte this crate does not define.
    UnknownKind(u8),
    /// A frame kind that is valid but is not a control message.
    NotControl(FrameKind),
    /// A payload that parsed as JSON but is not an object at the top level.
    NotAnObject,
    /// A required field is absent, or is `null`.
    MissingField(&'static str),
    /// A field is present but not the type or value this message requires.
    InvalidField(&'static str),
    /// A [`SessionOpen`] whose `frame_duration_ms` no session can have, and
    /// why: zero, or too long for a frame's length field at its rate.
    FrameDuration(AudioError),
    /// The payload was not valid JSON at all.
    Json(JsonError),
}

impl From<JsonError> for ControlError {
    fn from(error: JsonError) -> Self {
        Self::Json(error)
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind(byte) => write!(f, "{byte} is not a frame kind this crate defines"),
            Self::NotControl(kind) => write!(f, "{kind:?} is not a control message"),
            Self::NotAnObject => f.write_str("control payload is not a JSON object"),
            Self::MissingField(name) => write!(f, "missing field {name:?}"),
            Self::InvalidField(name) => write!(f, "field {name:?} has the wrong type or value"),
            Self::FrameDuration(error) => write!(f, "field \"frame_duration_ms\": {error}"),
            Self::Json(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for ControlError {}

#[cfg(test)]
mod tests {
    use super::{
        Answer, BargeIn, CallState, CallStateKind, ControlError, ControlMessage, DtmfDigit,
        DtmfReceived, DtmfSend, ErrorCode, ErrorMessage, FrameKind, Hangup, IncomingCall,
        OtherErrorCode, Reject, SessionOpen, Transfer, VoiceActivity,
    };
    use crate::audio::{AudioError, SampleRate};

    fn round_trips(message: &ControlMessage) {
        let kind = message.kind();
        let bytes = message.to_json_bytes().expect("no non-finite numbers");
        let decoded = ControlMessage::decode(kind.to_u8(), &bytes).expect("valid payload");
        assert_eq!(&decoded, message);
    }

    #[test]
    fn every_message_kind_survives_a_round_trip_through_json_bytes() {
        round_trips(&ControlMessage::SessionOpen(SessionOpen::new(
            SampleRate::Hz16000,
        )));
        round_trips(&ControlMessage::IncomingCall(IncomingCall {
            call_id: "call-1".to_owned(),
            caller: "sip:alice@example.com".to_owned(),
            display_name: Some("Alice".to_owned()),
        }));
        round_trips(&ControlMessage::IncomingCall(IncomingCall {
            call_id: "call-2".to_owned(),
            caller: "sip:bob@example.com".to_owned(),
            display_name: None,
        }));
        round_trips(&ControlMessage::Answer(Answer {
            call_id: "call-1".to_owned(),
        }));
        round_trips(&ControlMessage::Reject(Reject {
            call_id: "call-1".to_owned(),
            reason: Some("busy".to_owned()),
        }));
        round_trips(&ControlMessage::Hangup(Hangup {
            call_id: "call-1".to_owned(),
            reason: None,
        }));
        round_trips(&ControlMessage::DtmfReceived(DtmfReceived {
            call_id: "call-1".to_owned(),
            digit: DtmfDigit::new('5').expect("a valid digit"),
            duration_ms: Some(120),
        }));
        round_trips(&ControlMessage::DtmfSend(DtmfSend {
            call_id: "call-1".to_owned(),
            digit: DtmfDigit::new('#').expect("a valid digit"),
            duration_ms: None,
        }));
        round_trips(&ControlMessage::CallState(CallState {
            call_id: "call-1".to_owned(),
            state: CallStateKind::Ringing,
        }));
        round_trips(&ControlMessage::CallState(CallState {
            call_id: "call-1".to_owned(),
            state: CallStateKind::Answered,
        }));
        round_trips(&ControlMessage::CallState(CallState {
            call_id: "call-1".to_owned(),
            state: CallStateKind::Ended {
                reason: Some("remote hangup".to_owned()),
            },
        }));
        round_trips(&ControlMessage::Transfer(Transfer {
            call_id: "call-1".to_owned(),
            target: "sip:carol@example.com".to_owned(),
        }));
        round_trips(&ControlMessage::BargeIn(BargeIn {
            call_id: "call-1".to_owned(),
        }));
        round_trips(&ControlMessage::VoiceActivity(VoiceActivity {
            call_id: "call-1".to_owned(),
            speaking: true,
        }));
        round_trips(&ControlMessage::VoiceActivity(VoiceActivity {
            call_id: "call-1".to_owned(),
            speaking: false,
        }));
        round_trips(&ControlMessage::Error(ErrorMessage {
            call_id: Some("call-1".to_owned()),
            code: ErrorCode::UnknownCall,
            message: "no such call".to_owned(),
        }));
        round_trips(&ControlMessage::Error(ErrorMessage {
            call_id: None,
            code: ErrorCode::Other(
                OtherErrorCode::new("vendor_specific".to_owned()).expect("not a reserved code"),
            ),
            message: "custom".to_owned(),
        }));
    }

    #[test]
    fn session_open_without_a_frame_duration_defaults_to_twenty_milliseconds() {
        let message =
            ControlMessage::decode(FrameKind::SessionOpen.to_u8(), br#"{"sample_rate":8000}"#)
                .expect("valid payload");
        assert_eq!(
            message,
            ControlMessage::SessionOpen(SessionOpen::new(SampleRate::Hz8000))
        );
    }

    #[test]
    fn session_open_with_a_frame_duration_no_session_can_have_is_refused_where_it_is_read() {
        // before, both decoded, and a session opened on them failed later in
        // whatever first tried to fill a frame
        for (payload, why) in [
            (
                br#"{"sample_rate":8000,"frame_duration_ms":0}"#.as_slice(),
                AudioError::EmptyFrame,
            ),
            (
                br#"{"sample_rate":48000,"frame_duration_ms":1000}"#,
                AudioError::FrameTooLarge,
            ),
        ] {
            assert_eq!(
                ControlMessage::decode(FrameKind::SessionOpen.to_u8(), payload),
                Err(ControlError::FrameDuration(why)),
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
        // the longest frame the length field carries at 48 kHz still opens
        let longest = ControlMessage::decode(
            FrameKind::SessionOpen.to_u8(),
            br#"{"sample_rate":48000,"frame_duration_ms":682}"#,
        );
        assert!(longest.is_ok(), "{longest:?}");
    }

    #[test]
    fn a_session_open_no_session_can_have_is_not_written_either() {
        let open = ControlMessage::SessionOpen(SessionOpen {
            sample_rate: SampleRate::Hz8000,
            frame_duration_ms: 0,
        });
        assert_eq!(
            open.to_json_bytes(),
            Err(ControlError::FrameDuration(AudioError::EmptyFrame))
        );
    }

    #[test]
    fn session_open_with_a_sample_rate_outside_the_four_is_refused() {
        assert_eq!(
            ControlMessage::decode(FrameKind::SessionOpen.to_u8(), br#"{"sample_rate":44100}"#),
            Err(ControlError::InvalidField("sample_rate"))
        );
    }

    #[test]
    fn a_missing_required_field_is_refused() {
        assert_eq!(
            ControlMessage::decode(FrameKind::Answer.to_u8(), b"{}"),
            Err(ControlError::MissingField("call_id"))
        );
    }

    #[test]
    fn a_field_of_the_wrong_type_is_refused() {
        assert_eq!(
            ControlMessage::decode(FrameKind::Answer.to_u8(), br#"{"call_id":5}"#),
            Err(ControlError::InvalidField("call_id"))
        );
    }

    #[test]
    fn a_call_state_outside_the_three_named_states_is_refused() {
        assert_eq!(
            ControlMessage::decode(
                FrameKind::CallState.to_u8(),
                br#"{"call_id":"c","state":"paused"}"#
            ),
            Err(ControlError::InvalidField("state"))
        );
    }

    #[test]
    fn a_speaking_field_that_is_not_a_boolean_is_refused() {
        assert_eq!(
            ControlMessage::decode(
                FrameKind::VoiceActivity.to_u8(),
                br#"{"call_id":"c","speaking":"yes"}"#
            ),
            Err(ControlError::InvalidField("speaking"))
        );
    }

    #[test]
    fn a_dtmf_digit_outside_the_sixteen_event_alphabet_is_refused() {
        assert_eq!(
            ControlMessage::decode(
                FrameKind::DtmfSend.to_u8(),
                br#"{"call_id":"c","digit":"x"}"#
            ),
            Err(ControlError::InvalidField("digit"))
        );
        assert_eq!(
            ControlMessage::decode(
                FrameKind::DtmfSend.to_u8(),
                br#"{"call_id":"c","digit":"12"}"#
            ),
            Err(ControlError::InvalidField("digit"))
        );
        assert_eq!(DtmfDigit::new('0').map(DtmfDigit::get), Some('0'));
        assert_eq!(DtmfDigit::new('*').map(DtmfDigit::get), Some('*'));
        assert_eq!(DtmfDigit::new('D').map(DtmfDigit::get), Some('D'));
        assert_eq!(DtmfDigit::new('E'), None);
    }

    #[test]
    fn a_payload_that_is_not_a_json_object_is_refused() {
        assert_eq!(
            ControlMessage::decode(FrameKind::Answer.to_u8(), b"42"),
            Err(ControlError::NotAnObject)
        );
        assert_eq!(
            ControlMessage::decode(FrameKind::Answer.to_u8(), b"[1,2]"),
            Err(ControlError::NotAnObject)
        );
    }

    #[test]
    fn the_audio_kind_byte_is_not_a_control_message() {
        assert_eq!(
            ControlMessage::decode(FrameKind::Audio.to_u8(), b"{}"),
            Err(ControlError::NotControl(FrameKind::Audio))
        );
    }

    #[test]
    fn a_kind_byte_this_crate_does_not_define_is_refused() {
        assert_eq!(
            ControlMessage::decode(200, b"{}"),
            Err(ControlError::UnknownKind(200))
        );
    }

    #[test]
    fn malformed_json_in_the_payload_is_refused_not_swallowed() {
        assert!(matches!(
            ControlMessage::decode(FrameKind::Answer.to_u8(), b"{not json"),
            Err(ControlError::Json(_))
        ));
    }

    #[test]
    fn an_unrecognised_error_code_round_trips_as_other() {
        let bytes = br#"{"call_id":null,"code":"vendor_x","message":"m"}"#;
        let decoded =
            ControlMessage::decode(FrameKind::Error.to_u8(), bytes).expect("valid payload");
        assert_eq!(
            decoded,
            ControlMessage::Error(ErrorMessage {
                call_id: None,
                code: ErrorCode::Other(
                    OtherErrorCode::new("vendor_x".to_owned()).expect("not a reserved code")
                ),
                message: "m".to_owned(),
            })
        );
    }

    #[test]
    fn a_code_colliding_with_a_reserved_string_cannot_become_other() {
        // "internal" is one of ErrorCode's own six strings. On the wire a
        // code is nothing but that string, so an `Other` holding it would be
        // indistinguishable from `ErrorCode::Internal` and would read back
        // as one, silently changing identity. Refusing the collision at
        // construction is what rules that out, rather than the decode side
        // merely happening to prefer the reserved variant.
        assert_eq!(OtherErrorCode::new("internal".to_owned()), None);

        let bytes = br#"{"call_id":null,"code":"internal","message":"m"}"#;
        let decoded =
            ControlMessage::decode(FrameKind::Error.to_u8(), bytes).expect("valid payload");
        assert_eq!(
            decoded,
            ControlMessage::Error(ErrorMessage {
                call_id: None,
                code: ErrorCode::Internal,
                message: "m".to_owned(),
            })
        );
    }

    #[test]
    fn every_frame_kind_byte_maps_back_to_the_variant_it_came_from() {
        let kinds = [
            FrameKind::Audio,
            FrameKind::SessionOpen,
            FrameKind::IncomingCall,
            FrameKind::Answer,
            FrameKind::Reject,
            FrameKind::Hangup,
            FrameKind::DtmfReceived,
            FrameKind::DtmfSend,
            FrameKind::CallState,
            FrameKind::Transfer,
            FrameKind::BargeIn,
            FrameKind::Error,
            FrameKind::VoiceActivity,
        ];
        for kind in kinds {
            assert_eq!(FrameKind::try_from(kind.to_u8()), Ok(kind));
        }
    }
}
