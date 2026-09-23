// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Frame, audio and control brought together into what a caller actually
//! reads off the socket and writes back to it.
//!
//! Everything below is sans-I/O: [`Decoder`] consumes byte slices handed to
//! it and [`encode_audio`]/[`encode_control`] produce them. Nothing here
//! opens a socket, and nothing here knows whether the far end is a Unix
//! socket, TCP, or a WebSocket — the document says the framing is the same
//! on all three, so the difference is entirely the transport's problem.

use core::fmt;

use crate::audio::{AudioConfig, AudioError};
use crate::control::{ControlError, ControlMessage, FrameKind};
use crate::frame::{self, FrameDecoder, FrameError};

/// Largest control payload accepted, independent of the audio frame size.
///
/// Not from the document. Every control message this crate defines fits in a
/// few hundred bytes; this leaves room for a caller identity or an error
/// string an order of magnitude longer than any of them, without opening the
/// door to a JSON payload sized to exhaust memory.
pub const MAX_CONTROL_PAYLOAD: usize = 8192;

/// Turns bytes off the wire into messages: PCM checked against the session's
/// frame size, and control messages decoded from their JSON payload.
#[derive(Debug)]
pub struct Decoder {
    frames: FrameDecoder,
    audio: AudioConfig,
}

/// What [`Decoder::next_message`] hands back.
///
/// Audio borrows from the decoder's internal buffer; a control message owns
/// its strings regardless of where its bytes came from, so it is returned as
/// a plain [`ControlMessage`].
#[derive(Debug, PartialEq)]
pub enum Decoded<'a> {
    /// PCM, already checked against the session's frame size.
    Audio(&'a [u8]),
    /// A decoded control message.
    Control(ControlMessage),
}

impl Decoder {
    /// A decoder for a session opened at `audio`.
    ///
    /// The frame length bound is the larger of one audio frame and
    /// [`MAX_CONTROL_PAYLOAD`], so neither budget rejects the other's
    /// traffic.
    ///
    /// # Errors
    /// [`AudioError::FrameTooLarge`] if `audio`'s frame size does not fit the
    /// frame format's sixteen-bit length.
    pub fn new(audio: AudioConfig) -> Result<Self, AudioError> {
        let frame_bytes = usize::from(audio.frame_bytes()?);
        let max_payload = frame_bytes
            .max(MAX_CONTROL_PAYLOAD)
            .min(usize::from(u16::MAX));
        let max_payload = u16::try_from(max_payload).unwrap_or(u16::MAX);
        Ok(Self {
            frames: FrameDecoder::new(max_payload),
            audio,
        })
    }

    /// Take bytes off the transport.
    pub fn push(&mut self, bytes: &[u8]) {
        self.frames.push(bytes);
    }

    /// The next complete message, if one has arrived.
    ///
    /// `Ok(None)` means "not yet"; call again after more bytes.
    ///
    /// # Errors
    /// [`DecodeError`], for a frame whose length exceeds the session's bound,
    /// an audio frame of the wrong size, or a control message that failed to
    /// decode. Only the first is final — [`DecodeError::is_final`] — and the
    /// other two consumed their frame, so the next call reads on.
    pub fn next_message(&mut self) -> Result<Option<Decoded<'_>>, DecodeError> {
        let Self { frames, audio } = self;
        let Some(frame) = frames.next_frame()? else {
            return Ok(None);
        };
        if frame.kind() == FrameKind::Audio.to_u8() {
            audio.validate_frame(frame.payload())?;
            return Ok(Some(Decoded::Audio(frame.payload())));
        }
        let message = ControlMessage::decode(frame.kind(), frame.payload())?;
        Ok(Some(Decoded::Control(message)))
    }

    /// Forget everything buffered, as after the connection was replaced.
    pub fn reset(&mut self) {
        self.frames.reset();
    }
}

/// Write one audio frame.
///
/// # Errors
/// [`AudioError::WrongFrameSize`] if `payload` is not exactly one frame at
/// the session's rate and duration — half a frame is a bug on the caller's
/// side, and sending it anyway would hide that bug behind a click on the
/// wire. [`FrameError::PayloadTooLarge`] cannot happen for a payload that
/// already passed the frame-size check, since [`AudioConfig::frame_bytes`]
/// is itself bounded to sixteen bits.
pub fn encode_audio(
    audio: AudioConfig,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), EncodeError> {
    audio.validate_frame(payload)?;
    frame::write_frame(FrameKind::Audio.to_u8(), payload, out)?;
    Ok(())
}

/// Write one control message.
///
/// Held to [`MAX_CONTROL_PAYLOAD`], the bound every [`Decoder`] reads control
/// frames up to, rather than to the sixteen bits the length field could
/// carry: a frame longer than that is one the far end's decoder refuses as
/// final, which ends the connection over one message. Some fields come from
/// outside — [`crate::IncomingCall::caller`] and its display name are read
/// off a SIP request a stranger wrote — so the application shortens them
/// when this refuses, rather than this refusal being unreachable.
///
/// # Errors
/// See [`EncodeError`]; [`FrameError::PayloadTooLarge`] for a message whose
/// JSON is longer than [`MAX_CONTROL_PAYLOAD`], with nothing written.
pub fn encode_control(message: &ControlMessage, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let payload = message.to_json_bytes()?;
    if payload.len() > MAX_CONTROL_PAYLOAD {
        return Err(EncodeError::Frame(FrameError::PayloadTooLarge {
            declared: payload.len(),
            max: MAX_CONTROL_PAYLOAD,
        }));
    }
    frame::write_frame(message.kind().to_u8(), &payload, out)?;
    Ok(())
}

/// Why a message could not be decoded off the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The frame envelope itself.
    Frame(FrameError),
    /// An audio frame that was not the session's frame size.
    Audio(AudioError),
    /// A control message that did not decode.
    Control(ControlError),
}

impl DecodeError {
    /// Whether the stream can be read past this error at all.
    ///
    /// Only a [`DecodeError::Frame`] is final: a length that exceeds the
    /// bound leaves no way to know where the frame it announced ends, so
    /// nothing after it can be read and the connection has to go. An audio
    /// frame of the wrong size or a control message that did not decode was
    /// still a whole frame, already consumed, and the next call to
    /// [`Decoder::next_message`] reads the frame after it — the error belongs
    /// on the error channel ([`crate::ErrorMessage`]), not in a closed
    /// socket.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        matches!(self, Self::Frame(_))
    }
}

impl From<FrameError> for DecodeError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<AudioError> for DecodeError {
    fn from(error: AudioError) -> Self {
        Self::Audio(error)
    }
}

impl From<ControlError> for DecodeError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "{error}"),
            Self::Audio(error) => write!(f, "{error}"),
            Self::Control(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for DecodeError {}

/// Why a message could not be written to the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The frame envelope itself.
    Frame(FrameError),
    /// An audio frame that was not the session's frame size.
    Audio(AudioError),
    /// A control message whose JSON could not be written.
    Control(ControlError),
}

impl From<FrameError> for EncodeError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

impl From<AudioError> for EncodeError {
    fn from(error: AudioError) -> Self {
        Self::Audio(error)
    }
}

impl From<ControlError> for EncodeError {
    fn from(error: ControlError) -> Self {
        Self::Control(error)
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "{error}"),
            Self::Audio(error) => write!(f, "{error}"),
            Self::Control(error) => write!(f, "{error}"),
        }
    }
}

impl core::error::Error for EncodeError {}

#[cfg(test)]
mod tests {
    use super::{Decoded, Decoder, EncodeError, MAX_CONTROL_PAYLOAD, encode_audio, encode_control};
    use crate::audio::AudioConfig;
    use crate::audio::SampleRate;
    use crate::control::{Answer, ControlMessage, FrameKind, IncomingCall, SessionOpen};
    use crate::frame::{FrameError, write_frame};

    #[test]
    fn an_audio_frame_written_and_pushed_back_comes_out_as_audio() {
        let config = AudioConfig::new(SampleRate::Hz8000);
        let payload = vec![0_u8; usize::from(config.frame_bytes().expect("fits"))];
        let mut wire = Vec::new();
        encode_audio(config, &payload, &mut wire).expect("valid frame");

        let mut decoder = Decoder::new(config).expect("valid config");
        decoder.push(&wire);
        let got = decoder
            .next_message()
            .expect("no error")
            .expect("a message");
        assert_eq!(got, Decoded::Audio(payload.as_slice()));
        assert!(decoder.next_message().expect("no error").is_none());
    }

    #[test]
    fn a_control_message_written_and_pushed_back_comes_out_decoded() {
        let config = AudioConfig::new(SampleRate::Hz8000);
        let message = ControlMessage::Answer(Answer {
            call_id: "call-1".to_owned(),
        });
        let mut wire = Vec::new();
        encode_control(&message, &mut wire).expect("valid message");

        let mut decoder = Decoder::new(config).expect("valid config");
        decoder.push(&wire);
        let got = decoder
            .next_message()
            .expect("no error")
            .expect("a message");
        assert_eq!(got, Decoded::Control(message));
    }

    #[test]
    fn audio_and_control_interleave_in_the_order_they_were_pushed() {
        // this is the property the shared socket exists for: a barge-in
        // decoded ahead of audio frames pushed before it would be exactly
        // the ambiguity the document calls out
        let config = AudioConfig::new(SampleRate::Hz8000);
        let audio_payload = vec![7_u8; usize::from(config.frame_bytes().expect("fits"))];
        let open = ControlMessage::SessionOpen(SessionOpen::new(SampleRate::Hz8000));

        let mut wire = Vec::new();
        encode_control(&open, &mut wire).expect("valid message");
        encode_audio(config, &audio_payload, &mut wire).expect("valid frame");

        let mut decoder = Decoder::new(config).expect("valid config");
        decoder.push(&wire);
        assert_eq!(
            decoder.next_message().expect("no error"),
            Some(Decoded::Control(open))
        );
        assert_eq!(
            decoder.next_message().expect("no error"),
            Some(Decoded::Audio(audio_payload.as_slice()))
        );
    }

    #[test]
    fn an_audio_frame_of_the_wrong_size_is_refused_at_write_time() {
        let config = AudioConfig::new(SampleRate::Hz8000);
        let mut wire = Vec::new();
        assert!(matches!(
            encode_audio(config, &[0_u8; 3], &mut wire),
            Err(EncodeError::Audio(_))
        ));
        assert!(wire.is_empty());
    }

    #[test]
    fn a_control_message_longer_than_any_decoder_accepts_is_refused_when_written() {
        // the caller's identity comes off a SIP INVITE, whose From a peer
        // can make as long as a datagram allows; written anyway, the frame
        // is one every Decoder refuses as final, and the connection ends
        let message = ControlMessage::IncomingCall(IncomingCall {
            call_id: "call-1".to_owned(),
            caller: "sip:caller@example.com".to_owned(),
            display_name: Some("x".repeat(MAX_CONTROL_PAYLOAD)),
        });
        let mut wire = Vec::new();
        assert_eq!(
            encode_control(&message, &mut wire),
            Err(EncodeError::Frame(FrameError::PayloadTooLarge {
                declared: message.to_json_bytes().expect("finite").len(),
                max: MAX_CONTROL_PAYLOAD,
            }))
        );
        assert!(wire.is_empty(), "nothing half-written");
    }

    #[test]
    fn a_control_message_at_exactly_the_bound_is_written_and_read_back() {
        let bare = ControlMessage::IncomingCall(IncomingCall {
            call_id: "call-1".to_owned(),
            caller: "sip:caller@example.com".to_owned(),
            display_name: Some(String::new()),
        });
        let room = MAX_CONTROL_PAYLOAD - bare.to_json_bytes().expect("finite").len();
        let message = ControlMessage::IncomingCall(IncomingCall {
            call_id: "call-1".to_owned(),
            caller: "sip:caller@example.com".to_owned(),
            display_name: Some("x".repeat(room)),
        });
        assert_eq!(
            message.to_json_bytes().expect("finite").len(),
            MAX_CONTROL_PAYLOAD
        );
        let mut wire = Vec::new();
        encode_control(&message, &mut wire).expect("exactly at the bound");

        // the smallest decoder there is: 8 kHz, one millisecond a frame
        let config = AudioConfig::with_frame_duration_ms(SampleRate::Hz8000, 1).expect("fits");
        let mut decoder = Decoder::new(config).expect("valid config");
        decoder.push(&wire);
        assert_eq!(
            decoder.next_message().expect("no error"),
            Some(Decoded::Control(message))
        );
    }

    #[test]
    fn a_refused_audio_or_control_frame_does_not_desynchronise_what_follows() {
        let config = AudioConfig::new(SampleRate::Hz8000);
        let mut wire = Vec::new();
        write_frame(FrameKind::Audio.to_u8(), &[0_u8; 3], &mut wire).expect("written");
        write_frame(FrameKind::Answer.to_u8(), b"{not json", &mut wire).expect("written");
        write_frame(200, b"{}", &mut wire).expect("written");
        let answer = ControlMessage::Answer(Answer {
            call_id: "call-1".to_owned(),
        });
        encode_control(&answer, &mut wire).expect("valid message");

        let mut decoder = Decoder::new(config).expect("valid config");
        decoder.push(&wire);
        for _ in 0..3 {
            let error = decoder.next_message().expect_err("a refused frame");
            assert!(!error.is_final(), "{error} left the stream readable");
        }
        assert_eq!(
            decoder.next_message().expect("no error"),
            Some(Decoded::Control(answer))
        );
    }

    #[test]
    fn a_frame_declaring_more_than_the_session_bound_is_refused() {
        let config = AudioConfig::new(SampleRate::Hz8000);
        let mut decoder = Decoder::new(config).expect("valid config");
        // kind 1, length 0xFFFF: far past both the audio frame size and
        // MAX_CONTROL_PAYLOAD for an 8 kHz twenty-millisecond session
        decoder.push(&[1, 0xFF, 0xFF]);
        let error = decoder.next_message().expect_err("past the bound");
        assert!(error.is_final());
        // and it stays refused: nothing after a length that lied is readable
        assert!(decoder.next_message().is_err());
    }
}
