// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! What can go wrong where signalling meets media.
//!
//! Every variant is a refusal with a reason. An unknown codec is rejected where it is set, and a
//! call whose media could not open says so instead of standing up silent.

use core::fmt;

use sipral_core::sdp::SdpError;
#[cfg(feature = "opus")]
use sipral_media::opus::CodecError;
use sipral_ua::UaError;

use crate::codec::Codec;

/// Why a media operation did not happen.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MediaError {
    /// A codec order named the same codec twice, or one not in this build. Codecs are fixed at
    /// compile time, so this is a configuration error.
    UnsupportedCodec {
        /// What was asked for.
        name: String,
    },
    /// A codec order was empty. An offer has to name at least one format.
    NoCodecs,
    /// A packetisation interval no codec here can cut a frame at.
    BadFrameLength {
        /// What was asked for, in milliseconds.
        millis: u32,
    },
    /// The negotiation settled on a payload type this build cannot decode: the peer answered with
    /// something not in the offer.
    UnknownPayload {
        /// The type the answer named.
        payload: u8,
        /// What its `a=rtpmap` called it.
        encoding: String,
    },
    /// No dynamic payload type is left for a codec new to the call; RFC 3264 §8.3.2 forbids reusing
    /// a number within a session.
    NoPayloadType,
    /// The description this end wrote or the one that arrived could not be
    /// read.
    Description(SdpError),
    /// The two descriptions were read but they agree on nothing that can carry
    /// audio.
    NoCommonCodec,
    /// One end refused the stream with port zero (RFC 3264 §6). The call is up without audio, which
    /// a peer may want.
    StreamRefused,
    /// No session description to work from: an INVITE without a body answered without one, or a
    /// call whose media never opened.
    NoDescription,
    /// The call is not one this engine placed or answered.
    NoSuchCall,
    /// The negotiation would key the stream by DTLS and this build has no DTLS. Refused rather than
    /// opened in the clear; [`Capabilities`](crate::Capabilities) reports it before calling.
    NoDtlsSrtp,
    /// The DTLS key and certificate (RFC 8122) could not be made. Only a media seed that is not
    /// real entropy causes this; see [`MediaEngine::new`](crate::MediaEngine::new).
    #[cfg(feature = "dtls")]
    DtlsIdentity,
    /// The two `a=setup` values are incompatible, so neither end knows who sends the ClientHello
    /// (RFC 4145 §4.1, RFC 5763 §5).
    ///
    /// Refused up front: otherwise both ends act as server and wait two minutes with no audio and
    /// no error.
    #[cfg(feature = "dtls")]
    DtlsRole,
    /// The peer's `a=fingerprint` is unreadable or uses a hash this build lacks (RFC 8122 §5).
    /// Without it the handshake would accept anyone.
    #[cfg(feature = "dtls")]
    DtlsFingerprint,
    /// The handshake produced no keys: wrong certificate for the signalled fingerprint (RFC 8122
    /// §5.1), nothing keyable offered, an alert, or no answer.
    ///
    /// The call is left up for the application to decide, but no audio flows: a stream that agreed
    /// to encryption never falls back to clear.
    #[cfg(feature = "dtls")]
    DtlsHandshake,
    /// The far end closed the DTLS connection before it was keyed, or while
    /// it was running (RFC 6347 §4.2.8).
    #[cfg(feature = "dtls")]
    DtlsClosed,
    /// The handshake agreed an SRTP profile this build has no transform for (RFC 5764 §4.1.2).
    /// Unreachable from a peer; it catches a profile added to the handshake but not to the stream.
    #[cfg(feature = "dtls")]
    DtlsProfile,
    /// DTLS-SRTP was agreed without rtcp-mux, which would need a second handshake on the RTCP port
    /// (RFC 5764 §4.2); this stack runs one. Our DTLS offers always ask for mux, so the peer
    /// removed it.
    #[cfg(feature = "dtls")]
    DtlsNeedsRtcpMux,
    /// A renegotiation named a different far-end certificate (RFC 5763 §6.6).
    ///
    /// That requires a new DTLS association, which this stack does not start. A re-offer naming one
    /// is answered 488 (RFC 8842 §5.3); an answer naming one is not adopted. The session keeps its
    /// keys and the call is told, instead of trusting an unchecked certificate.
    #[cfg(feature = "dtls")]
    DtlsFingerprintChanged,
    /// A renegotiation would change how a running stream is keyed: encryption on or off, or SDES to
    /// DTLS-SRTP or back.
    ///
    /// A running stream cannot switch. A re-offer asking for it is answered 488, an answer doing it
    /// is not adopted; the session continues unchanged and the call is told.
    KeyingChanged,
    /// A renegotiation would swap the DTLS client and server roles (RFC 8842 §3.1).
    ///
    /// Refused like a changed certificate: a re-offer gets 488, an answer is not adopted, the
    /// association continues. Our own offers send `actpass` (§5.5), so a peer keeping the
    /// association answers with the current roles (§5.3).
    #[cfg(feature = "dtls")]
    DtlsRoleChanged,
    /// The ICE agent refused its input: a candidate address RFC 8445 §5.1.1.1 rules out,
    /// credentials outside RFC 8839 §5.4, or a peer that changed credentials without a restart. The
    /// cause is kept because these are different faults: our configuration, a bad peer fragment, an
    /// unannounced restart.
    #[cfg(feature = "ice")]
    Ice(sipral_nat::ice::IceError),
    /// The call requires ICE ([`IcePolicy::Required`]) and the far end described none usable: no
    /// attributes, no pairable candidates, or default destinations missing from its candidates (RFC
    /// 8839 §4.2.5). Under [`IcePolicy::Offered`] each of these falls back to the signalled
    /// address.
    ///
    /// [`IcePolicy::Required`]: crate::IcePolicy::Required
    /// [`IcePolicy::Offered`]: crate::IcePolicy::Offered
    #[cfg(feature = "ice")]
    IceRequired,
    /// ICE was offered and rtcp-mux was not agreed, leaving an RTCP component with no address. As
    /// for [`MediaError::DtlsNeedsRtcpMux`]: our ICE offers always ask for mux, so the peer removed
    /// it.
    #[cfg(feature = "ice")]
    IceNeedsRtcpMux,
    /// Consent on the selected pair is gone: no authenticated response for 30 s, or a 403 (RFC 7675
    /// §5).
    ///
    /// Nothing more may be sent on the pair, and its credentials are spent. Restart ICE
    /// ([`MediaEngine::restart_ice`](crate::MediaEngine::restart_ice)) or end the call.
    #[cfg(feature = "ice")]
    IcePathLost,
    /// [`MediaEngine::restart_ice`](crate::MediaEngine::restart_ice) on a call without an ICE agent
    /// (no ICE offered or answered, or no session yet). Nothing is sent.
    #[cfg(feature = "ice")]
    NoIce,
    /// [`MediaEngine::readdress`](crate::MediaEngine::readdress) on a call running ICE. Nothing is
    /// sent: moving only `c=` and `m=` would contradict the candidates (RFC 8839 §4.2.5); such a
    /// call moves by an ICE restart on the new socket.
    #[cfg(feature = "ice")]
    MovesWithIce,
    /// The call requires SRTP and would have carried audio without it: a plain offer or re-offer to
    /// a [`SrtpPolicy::Required`] call, a plain answer to its offer, or an answer keyed the way its
    /// policy forbids.
    ///
    /// The call is refused, never silently downgraded: an INVITE or re-offer gets 488 (RFC 3261
    /// §21.4.26), and a call we placed that was answered plainly is hung up with `Reason` 488 (RFC
    /// 3326) once its 2xx is acknowledged (§13.2.2.4).
    ///
    /// [`SrtpPolicy::Required`]: crate::SrtpPolicy::Required
    SrtpRequired,
    /// The description would carry an SDES key over unencrypted signalling while the catalogue says
    /// [`SdesSignalling::SecureOnly`](crate::SdesSignalling::SecureOnly) (RFC 4568 §8.3). Nothing
    /// was sent: an outgoing call was not placed, an incoming one is still ringing for the
    /// application to reject.
    KeysWouldTravelInClear,
    /// A list of SRTP suites that names none, or names one twice
    /// ([`CodecCatalog::with_srtp_suites`](crate::CodecCatalog::with_srtp_suites)).
    NoSrtpSuite,
    /// The agreed crypto line asks for terms this build does not support: several master keys, an
    /// RFC 4568 §6.3 parameter disabling encryption or authentication, a key derivation rate, or an
    /// unreadable mandatory parameter. Refused, because a stream on terms only one end believes
    /// looks like a network fault.
    UnusableKeying,
    /// The codec refused a frame. Only Opus can, for a frame length it was not set up for; the
    /// variant exists only with the `opus` feature.
    #[cfg(feature = "opus")]
    Codec(CodecError),
    /// The packet did not fit the buffer it had to be built in.
    PacketTooLong {
        /// What it needed.
        need: usize,
        /// What there was.
        got: usize,
    },
    /// A render-to-capture delay longer than any loudspeaker-to-microphone path. Such a value is a
    /// platform reporting something else, so it is refused where it is set.
    RenderDelayTooLong {
        /// What was asked for.
        asked: std::time::Duration,
        /// The longest this build keeps history for.
        most: std::time::Duration,
    },
    /// A digit shorter than legacy equipment recognises.
    DigitTooShort {
        /// What was asked for.
        asked: std::time::Duration,
        /// The floor RFC 4733 §2.5.2.1 takes from ITU-T Q.24.
        least: std::time::Duration,
    },
    /// A digit longer than any key is held; the same ceiling as INFO digits.
    DigitTooLong {
        /// What was asked for.
        asked: std::time::Duration,
        /// The longest a digit may last.
        most: std::time::Duration,
    },
    /// More digits than one call will hold waiting.
    TooManyDigits,
    /// A dial string held a character no keypad has.
    UnknownDigit {
        /// The character.
        key: char,
    },
    /// A recording could not start, or stopped part-way. Carries the error kind so the event stays
    /// comparable and cloneable; the call continues.
    Recording(std::io::ErrorKind),
    /// Nothing is being recorded on this call.
    NotRecording,
    /// A recording was asked for while one runs; two writers would interleave frames.
    AlreadyRecording,
    /// A recording rate the format cannot write: outside 8 to 48 kHz for WAV, or not one of Opus's
    /// five rates for Ogg Opus.
    RecordingRate {
        /// What was asked for.
        hertz: u32,
    },
    /// An application rate that is not one of
    /// [`APPLICATION_RATES`](crate::APPLICATION_RATES).
    ApplicationRate {
        /// What was asked for.
        hertz: u32,
    },
    /// An Ogg Opus recording was asked for at a bitrate Opus is not defined
    /// at.
    RecordingBitrate {
        /// What was asked for.
        bits_per_second: u32,
    },
    /// A consent tone that no codec here carries, or that is not a beep:
    /// the sentence names the field.
    ConsentTone(&'static str),
    /// The user agent refused the request the media was for.
    Signalling(UaError),
    /// [`MediaEngine::join`](crate::MediaEngine::join) was asked to join a
    /// call to itself.
    SameCall,
    /// [`MediaEngine::join`](crate::MediaEngine::join) on a call already paired. Leave first
    /// ([`MediaEngine::leave`](crate::MediaEngine::leave)); [`mix_two`](crate::mix_two) mixes
    /// exactly two far ends and this end.
    AlreadyJoined,
    /// [`MediaEngine::leave`](crate::MediaEngine::leave) or
    /// [`MediaEngine::mix`](crate::MediaEngine::mix) was asked about a call
    /// that is not currently joined to another.
    NotJoined,
    /// [`MediaEngine::join`](crate::MediaEngine::join) on calls with different sample rates or
    /// frame lengths. [`mix_two`](crate::mix_two) does not resample, so samples must line up one to
    /// one.
    JoinIncompatible,
    /// A [`LocalConference`](crate::LocalConference) has no place left, or
    /// was asked to be made with none or with more than
    /// [`MAX_CONFERENCE_MEMBERS`](crate::MAX_CONFERENCE_MEMBERS).
    ConferenceFull {
        /// How many members it holds, this end included.
        capacity: usize,
    },
    /// A call a [`LocalConference`](crate::LocalConference) cannot mix: a rate other than 8, 16, 32
    /// or 48 kHz, or frames over 60 ms. A conference made for this end at such a rate is refused
    /// the same way.
    ConferenceIncompatible {
        /// The rate asked for.
        hertz: u32,
        /// The frame asked for, in samples at that rate.
        frame_samples: usize,
    },
    /// The call is already in a [`LocalConference`](crate::LocalConference) or a
    /// [`MediaEngine::join`](crate::MediaEngine::join) pair; two drivers would each take half the
    /// frames.
    InConference,
    /// A member not in the [`LocalConference`](crate::LocalConference): never added, already gone,
    /// or this end in a conference made without it.
    NotInConference,
    /// A [`LocalConference`](crate::LocalConference) is recorded as one mix,
    /// in one channel; a stereo layout has nothing to put on its second.
    ConferenceStereo,
    /// This end's own frame handed to a
    /// [`LocalConference`](crate::LocalConference) was not one tick long.
    LocalFrame {
        /// Samples in a tick at this end's rate.
        expected: usize,
        /// Samples given.
        given: usize,
    },
    /// Text on a call without an RFC 4103 text stream: no text socket
    /// ([`CallMedia::text`](crate::CallMedia::text)), the far end refused or never offered one, or
    /// the audio is keyed.
    NoText,
    /// More text than the call holds unsent; none of it was queued.
    TextBufferFull {
        /// Characters there is still room for.
        room: usize,
    },
}

impl MediaError {
    /// The codec this build lacks, when that is the error, so a failed call can be logged with its
    /// name.
    #[must_use]
    pub fn unsupported(codec: &str) -> Self {
        Self::UnsupportedCodec {
            name: codec.to_owned(),
        }
    }

    /// Whether this is the codec's own refusal.
    ///
    // the variant is Opus's and exists only where Opus does, so the link has
    // to as well or a build without it documents a variant it has not got
    #[cfg_attr(
        feature = "opus",
        doc = "That is [`MediaError::Codec`], and it is what Opus produces \
               for a frame it was not built to cut."
    )]
    #[cfg_attr(
        not(feature = "opus"),
        doc = "The variant that would say so is Opus's, this build has no \
               Opus, and so this is always `false`."
    )]
    ///
    /// Asked rather than matched, because the variant exists only where Opus
    /// does and a crate above this one cannot write that `cfg`: a Cargo
    /// feature belongs to the crate that declares it, so an arm written
    /// under `sipral-ffi`'s own `opus` goes missing in a build whose facade
    /// linked the codec, and the refusal falls through to whatever the
    /// catch-all beneath it says.
    #[must_use]
    pub const fn is_codec(&self) -> bool {
        #[cfg(feature = "opus")]
        {
            matches!(*self, Self::Codec(_))
        }
        #[cfg(not(feature = "opus"))]
        {
            false
        }
    }
}

impl From<SdpError> for MediaError {
    fn from(error: SdpError) -> Self {
        Self::Description(error)
    }
}

#[cfg(feature = "opus")]
impl From<CodecError> for MediaError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<UaError> for MediaError {
    fn from(error: UaError) -> Self {
        Self::Signalling(error)
    }
}

impl From<std::io::Error> for MediaError {
    fn from(error: std::io::Error) -> Self {
        Self::Recording(error.kind())
    }
}

impl MediaError {
    /// The sentence for mixing refusals (pair or local conference) and application rate errors,
    /// split out of `Display` like `about_the_path`.
    fn about_mixing(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SameCall => f.write_str("a call cannot be joined to itself"),
            Self::ApplicationRate { hertz } => write!(
                f,
                "an application rate of {hertz} Hz; it is 8000, 16000, 24000 or 48000"
            ),
            Self::AlreadyJoined => f.write_str("this call is already joined to another"),
            Self::NotJoined => f.write_str("this call is not currently joined to another"),
            Self::JoinIncompatible => f.write_str(
                "the two calls decode at different sample rates, or cut audio into frames of \
                 different lengths, so they cannot be mixed without resampling",
            ),
            Self::ConferenceFull { capacity } => {
                write!(
                    f,
                    "the conference holds {capacity} members and has no place left"
                )
            }
            Self::ConferenceIncompatible {
                hertz,
                frame_samples,
            } => write!(
                f,
                "a conference mixes 8, 16, 32 and 48 kHz with frames of up to 60 ms, and this \
                 is {hertz} Hz with frames of {frame_samples} samples"
            ),
            Self::InConference => f.write_str(
                "this call is already in a conference or joined into a pair, which drives it",
            ),
            Self::NotInConference => f.write_str("that member is not in the conference"),
            Self::ConferenceStereo => {
                f.write_str("a conference is recorded as one mix, in one channel, not in stereo")
            }
            Self::LocalFrame { expected, given } => write!(
                f,
                "this end's frame in a conference is {expected} samples, and {given} were given"
            ),
            _ => f.write_str(UNNAMED),
        }
    }

    /// The sentences for refusals about securing a call and choosing its path, split out of
    /// [`fmt::Display`] to keep that match readable. `None` for everything else.
    fn about_the_path(&self) -> Option<&'static str> {
        Some(match self {
            #[cfg(feature = "dtls")]
            Self::DtlsFingerprint => "the peer's a=fingerprint could not be read",
            #[cfg(feature = "dtls")]
            Self::DtlsHandshake => "the DTLS handshake produced no keys",
            #[cfg(feature = "dtls")]
            Self::DtlsClosed => "the far end closed the DTLS connection before it was keyed",
            #[cfg(feature = "dtls")]
            Self::DtlsProfile => "the handshake agreed an SRTP profile this build cannot open",
            #[cfg(feature = "dtls")]
            Self::DtlsNeedsRtcpMux => {
                "DTLS-SRTP here needs RTP and RTCP on one port, and the answer did not"
            }
            #[cfg(feature = "dtls")]
            Self::DtlsFingerprintChanged => {
                "the far end named a different certificate part-way through the call"
            }
            Self::KeyingChanged => {
                "the far end asked to change how the call is encrypted part-way through"
            }
            #[cfg(feature = "dtls")]
            Self::DtlsRoleChanged => {
                "the far end asked to swap the DTLS client and server part-way through the call"
            }
            #[cfg(feature = "ice")]
            Self::IceRequired => {
                "this call requires ICE and the far end described none it could use"
            }
            #[cfg(feature = "ice")]
            Self::IceNeedsRtcpMux => {
                "ICE here needs RTP and RTCP on one port, and the answer did not"
            }
            #[cfg(feature = "ice")]
            Self::IcePathLost => "consent to send on the path ICE selected has been withdrawn",
            #[cfg(feature = "ice")]
            Self::NoIce => "this call runs no ICE agent to restart",
            #[cfg(feature = "ice")]
            Self::MovesWithIce => {
                "this call runs ICE, which moves by a restart and not a new address"
            }
            Self::SrtpRequired => "this call requires SRTP and the far end described none",
            Self::KeysWouldTravelInClear => {
                "an SDES key would travel in signalling that is not encrypted, and this call \
                 takes SDES over TLS only"
            }
            Self::NoSrtpSuite => {
                "a list of SRTP suites must name each suite once, and at least one"
            }
            Self::UnusableKeying => "the crypto line asks for terms this build will not be held to",
            _ => return None,
        })
    }
}

/// Fallback text for a variant with no sentence. Unreachable:
/// `every_media_error_says_something_of_its_own` checks every variant is covered. A panicking
/// `Display` would turn a log line into an abort.
const UNNAMED: &str = "this call's media was refused and this build has no sentence for why";

impl fmt::Display for MediaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "ice")]
            Self::Ice(error) => write!(f, "ice: {error}"),
            Self::UnsupportedCodec { name } => {
                write!(f, "this build has no codec called {name}; it has ")?;
                for (index, codec) in Codec::ALL.iter().enumerate() {
                    if index > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(codec.name())?;
                }
                Ok(())
            }
            Self::NoCodecs => f.write_str("a codec order with nothing in it"),
            Self::BadFrameLength { millis } => {
                write!(f, "no codec here cuts a frame at {millis} ms")
            }
            Self::UnknownPayload { payload, encoding } => {
                write!(
                    f,
                    "the answer settled on {encoding}, payload type {payload}, which this build cannot decode"
                )
            }
            Self::NoPayloadType => f.write_str(
                "every dynamic payload type has already named another codec on this call",
            ),
            Self::Description(error) => write!(f, "session description: {error}"),
            Self::NoCommonCodec => f.write_str("the two descriptions have no codec in common"),
            Self::StreamRefused => {
                f.write_str("the stream was refused, so the call carries no audio")
            }
            Self::NoDescription => f.write_str("no session description has been agreed"),
            Self::NoSuchCall => f.write_str("no such call"),
            Self::NoDtlsSrtp => {
                f.write_str("the keys were to come from a DTLS handshake, which this build has no")
            }
            #[cfg(feature = "dtls")]
            Self::DtlsIdentity => f.write_str("no key and certificate could be made for DTLS-SRTP"),
            #[cfg(feature = "dtls")]
            Self::DtlsRole => {
                f.write_str("the two a=setup values do not say which end starts the handshake")
            }
            #[cfg(feature = "opus")]
            Self::Codec(error) => write!(f, "codec: {error}"),
            Self::PacketTooLong { need, got } => {
                write!(f, "the packet needs {need} octets and there are {got}")
            }
            Self::RenderDelayTooLong { asked, most } => write!(
                f,
                "a render-to-capture delay of {} ms; this build keeps {} ms of history",
                asked.as_millis(),
                most.as_millis()
            ),
            Self::DigitTooShort { asked, least } => write!(
                f,
                "a digit of {} ms; equipment recognises {} ms and up",
                asked.as_millis(),
                least.as_millis()
            ),
            Self::DigitTooLong { asked, most } => write!(
                f,
                "a digit of {} ms; no key is held for more than {} ms",
                asked.as_millis(),
                most.as_millis()
            ),
            Self::TooManyDigits => f.write_str("too many digits are already waiting to be sent"),
            Self::UnknownDigit { key } => write!(f, "no keypad has {key:?}"),
            Self::Recording(kind) => write!(f, "recording: {kind}"),
            Self::NotRecording => f.write_str("nothing is being recorded on this call"),
            Self::AlreadyRecording => f.write_str("this call is already being recorded"),
            Self::RecordingRate { hertz } => {
                write!(
                    f,
                    "a recording in this format cannot be written at {hertz} Hz"
                )
            }
            Self::RecordingBitrate { bits_per_second } => write!(
                f,
                "an Ogg Opus recording cannot be written at {bits_per_second} bit/s"
            ),
            Self::ConsentTone(what) => write!(f, "consent tone: {what}"),
            Self::Signalling(error) => write!(f, "user agent: {error}"),
            Self::SameCall
            | Self::ApplicationRate { .. }
            | Self::AlreadyJoined
            | Self::NotJoined
            | Self::JoinIncompatible
            | Self::ConferenceFull { .. }
            | Self::ConferenceIncompatible { .. }
            | Self::InConference
            | Self::NotInConference
            | Self::ConferenceStereo
            | Self::LocalFrame { .. } => self.about_mixing(f),
            Self::NoText => f.write_str("the call negotiated no real-time text stream"),
            Self::TextBufferFull { room } => write!(
                f,
                "the text does not fit: there is room for {room} more characters unsent"
            ),
            // refusals about security and path, kept in `about_the_path`
            other => f.write_str(other.about_the_path().unwrap_or(UNNAMED)),
        }
    }
}

impl core::error::Error for MediaError {}

#[cfg(test)]
mod tests {
    use super::{MediaError, UNNAMED};

    /// `UNNAMED` stays unreachable: a variant added to neither match would print it, and this test
    /// notices first.
    #[test]
    fn every_media_error_says_something_of_its_own() {
        let refusals = [
            MediaError::NoCodecs,
            MediaError::NoCommonCodec,
            MediaError::NoPayloadType,
            MediaError::StreamRefused,
            MediaError::NoDescription,
            MediaError::NoSuchCall,
            MediaError::NoDtlsSrtp,
            MediaError::SrtpRequired,
            MediaError::NoSrtpSuite,
            MediaError::UnusableKeying,
            MediaError::TooManyDigits,
            MediaError::NotRecording,
            MediaError::AlreadyRecording,
            MediaError::RecordingRate { hertz: 44_100 },
            MediaError::ApplicationRate { hertz: 44_100 },
            MediaError::RecordingBitrate { bits_per_second: 1 },
            MediaError::ConsentTone("frequency_hz is outside 300 to 3400"),
            MediaError::SameCall,
            MediaError::AlreadyJoined,
            MediaError::NotJoined,
            MediaError::JoinIncompatible,
            MediaError::ConferenceFull { capacity: 3 },
            MediaError::ConferenceIncompatible {
                hertz: 44_100,
                frame_samples: 882,
            },
            MediaError::InConference,
            MediaError::NotInConference,
            MediaError::ConferenceStereo,
            MediaError::LocalFrame {
                expected: 320,
                given: 160,
            },
            #[cfg(feature = "dtls")]
            MediaError::DtlsIdentity,
            #[cfg(feature = "dtls")]
            MediaError::DtlsRole,
            #[cfg(feature = "dtls")]
            MediaError::DtlsFingerprint,
            #[cfg(feature = "dtls")]
            MediaError::DtlsHandshake,
            #[cfg(feature = "dtls")]
            MediaError::DtlsClosed,
            #[cfg(feature = "dtls")]
            MediaError::DtlsProfile,
            #[cfg(feature = "dtls")]
            MediaError::DtlsNeedsRtcpMux,
            #[cfg(feature = "dtls")]
            MediaError::DtlsFingerprintChanged,
            #[cfg(feature = "dtls")]
            MediaError::DtlsRoleChanged,
            MediaError::KeyingChanged,
            #[cfg(feature = "ice")]
            MediaError::Ice(sipral_nat::ice::IceError::NoUsableHost),
            #[cfg(feature = "ice")]
            MediaError::IceRequired,
            #[cfg(feature = "ice")]
            MediaError::IceNeedsRtcpMux,
            #[cfg(feature = "ice")]
            MediaError::IcePathLost,
            #[cfg(feature = "ice")]
            MediaError::NoIce,
            #[cfg(feature = "ice")]
            MediaError::MovesWithIce,
        ];
        let mut said: Vec<String> = Vec::new();
        for refusal in refusals {
            let sentence = refusal.to_string();
            assert_ne!(sentence, UNNAMED, "{refusal:?} has no sentence of its own");
            assert!(!sentence.is_empty(), "{refusal:?} says nothing at all");
            assert!(
                !said.contains(&sentence),
                "{refusal:?} says what another refusal already said: {sentence}"
            );
            said.push(sentence);
        }
    }
}
