// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What can go wrong where signalling meets media.
//!
//! Every variant here is a refusal with a reason, never a silence. A codec
//! order naming something this build does not contain is rejected where it is
//! set rather than ignored where it is used, and a call whose media could not
//! be opened says so instead of standing up with no audio in it.

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
    /// A codec order named the same codec twice, or named one that is not in
    /// this build.
    ///
    /// The set of codecs is a compile-time fact, so this is the answer a
    /// configuration gets, not a run-time surprise later.
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
    /// The negotiation settled on a payload type this build cannot decode.
    ///
    /// It means the peer answered with something that was not in the offer,
    /// which happens, and it is better said than played as noise.
    UnknownPayload {
        /// The type the answer named.
        payload: u8,
        /// What its `a=rtpmap` called it.
        encoding: String,
    },
    /// A codec new to the call cannot be offered on it: every dynamic payload
    /// type number has already been given to something else, and RFC 3264
    /// §8.3.2 does not let a number be given again within a session.
    NoPayloadType,
    /// The description this end wrote or the one that arrived could not be
    /// read.
    Description(SdpError),
    /// The two descriptions were read but they agree on nothing that can carry
    /// audio.
    NoCommonCodec,
    /// One end refused the stream: a port of zero in the answer, which
    /// RFC 3264 §6 makes the way to say no to an offered stream. The call is
    /// up and carries no audio, which is a thing a peer is allowed to want.
    StreamRefused,
    /// There is no session description to work from: an INVITE with no body
    /// that was answered without one either, or a call whose media was never
    /// opened.
    NoDescription,
    /// The call is not one this engine placed or answered.
    NoSuchCall,
    /// The negotiation would have keyed the stream from a DTLS handshake, and
    /// there is no DTLS in this build.
    ///
    /// Refused rather than opened in the clear on a secure profile. The whole
    /// of what a build without the `dtls` feature does about keys is SDES, and
    /// [`Capabilities`](crate::Capabilities) says so before a call is placed.
    NoDtlsSrtp,
    /// This stack could not make the key and certificate it would have
    /// presented (RFC 8122).
    ///
    /// The one way to reach it is a media seed that is not entropy, which is
    /// the caller's to supply and the one thing about SRTP that fails
    /// silently everywhere else: see
    /// [`MediaEngine::new`](crate::MediaEngine::new).
    #[cfg(feature = "dtls")]
    DtlsIdentity,
    /// The two `a=setup` values cannot both be honoured, so neither end knows
    /// which of them sends the ClientHello (RFC 4145 §4.1, RFC 5763 §5).
    ///
    /// Refused here rather than left to the handshake, because the failure it
    /// would otherwise cause is the quiet one: two ends that both believe
    /// they are the server wait for each other until the handshake gives up,
    /// which is two minutes of a call with no audio and no error.
    #[cfg(feature = "dtls")]
    DtlsRole,
    /// The peer's `a=fingerprint` cannot be read, or names a hash function
    /// this build has no implementation of (RFC 8122 §5).
    ///
    /// A fingerprint that cannot be read cannot authenticate anything, and a
    /// handshake run without one is a handshake with whoever answers.
    #[cfg(feature = "dtls")]
    DtlsFingerprint,
    /// The handshake did not produce keys: the peer's certificate is not the
    /// one its signalling named (RFC 8122 §5.1), it offered nothing this end
    /// can key with, it sent an alert, or it never answered at all.
    ///
    /// The call itself is untouched — whether to hang it up is a decision
    /// with a person on the other end of it — but no audio will flow, because
    /// a stream that agreed to be secured is never opened in the clear
    /// instead.
    #[cfg(feature = "dtls")]
    DtlsHandshake,
    /// The far end closed the DTLS connection before it was keyed, or while
    /// it was running (RFC 6347 §4.2.8).
    #[cfg(feature = "dtls")]
    DtlsClosed,
    /// The handshake agreed an SRTP protection profile this build has no
    /// transform for (RFC 5764 §4.1.2).
    ///
    /// Not reachable against a peer, since only profiles this end offered can
    /// be agreed; it is the arm a profile added to the handshake and not to
    /// the stream would land in, loudly, rather than opening a stream under
    /// the wrong transform.
    #[cfg(feature = "dtls")]
    DtlsProfile,
    /// The call agreed DTLS-SRTP and did not agree to multiplex its control
    /// traffic, so RFC 5764 §4.2 would need a second handshake on the RTCP
    /// port and this stack runs one.
    ///
    /// Refused rather than opened with an SRTCP half nothing will ever key.
    /// An offer written under a DTLS policy always asks for `a=rtcp-mux`, so
    /// the peer is one that took the attribute out of its answer.
    #[cfg(feature = "dtls")]
    DtlsNeedsRtcpMux,
    /// A re-negotiation named a different certificate for the far end
    /// (RFC 5763 §6.6).
    ///
    /// §6.6 asks for a new DTLS association there, and this stack does not
    /// start one: a re-offer from the far end that names one is answered 488
    /// (RFC 8842 §5.3 has an answerer that will not start the association
    /// refuse it), an answer that names one is not adopted, and either way
    /// the session keeps running on keys both ends still agree on and the
    /// call is told. Carrying on silently would be worse than either — the
    /// far end would have moved to a certificate this end never checked, and
    /// the media would keep flowing as though it had.
    #[cfg(feature = "dtls")]
    DtlsFingerprintChanged,
    /// A re-negotiation would change how a running stream is keyed: turn
    /// encryption on or off, or move it between SDES and a DTLS-SRTP
    /// handshake.
    ///
    /// A stream that has sent under one kind of keying has no way to carry
    /// on under another, and adopting the plan anyway left it running the
    /// old kind while the far end ran the new — encrypted audio to a peer
    /// expecting it in the clear, or the reverse, and a call that went silent
    /// with nothing said. So a re-offer that asks for it is answered 488 and
    /// an answer that does it is not adopted; either way the session keeps
    /// running as it was, and the call is told.
    KeyingChanged,
    /// A re-negotiation would swap which end is the DTLS client and which the
    /// server (RFC 8842 §3.1).
    ///
    /// The same new association a moved certificate asks for, and refused the
    /// same way: a re-offer from the far end that asks for it is answered
    /// 488, an answer that takes it is not adopted, and either way the session
    /// keeps running on the association it has. An offer from this end hands
    /// the choice back with `actpass` (§5.5), so a far end that keeps the
    /// association answers with the roles already in force (§5.3) and never
    /// reaches this.
    #[cfg(feature = "dtls")]
    DtlsRoleChanged,
    /// The ICE agent refused what it was given: an address RFC 8445 §5.1.1.1
    /// rules out of a candidate, credentials outside RFC 8839 §5.4's shape,
    /// or a peer that changed its credentials without restarting ICE.
    ///
    /// The cause is carried rather than flattened, because the three are
    /// different faults: the first is this end's own configuration, the
    /// second is a peer that wrote a fragment nobody can use, and the third
    /// is a peer that restarted ICE without saying so.
    #[cfg(feature = "ice")]
    Ice(sipral_nat::ice::IceError),
    /// The call is set to [`IcePolicy::Required`] and the far end described
    /// no usable ICE: no attributes at all, candidates none of which can be
    /// paired, or a description whose default destinations are missing from
    /// its own candidate lines (RFC 8839 §4.2.5, an ICE mismatch).
    ///
    /// Under [`IcePolicy::Offered`] every one of those is a fallback to the
    /// signalled address instead, which is the whole difference between the
    /// two and the reason they are separate settings.
    ///
    /// [`IcePolicy::Required`]: crate::IcePolicy::Required
    /// [`IcePolicy::Offered`]: crate::IcePolicy::Offered
    #[cfg(feature = "ice")]
    IceRequired,
    /// The call offered ICE and did not agree to multiplex its control
    /// traffic, so the stream has an RTCP component whose address this end
    /// cannot name.
    ///
    /// The mirror of [`MediaError::DtlsNeedsRtcpMux`], and refused for the
    /// same shape of reason: an offer written under an ICE policy always asks
    /// for `a=rtcp-mux`, so this is a peer that took the attribute out, and
    /// an offer that named a second component without a second address would
    /// fail this stack's own mismatch check.
    #[cfg(feature = "ice")]
    IceNeedsRtcpMux,
    /// Consent to send on the pair ICE selected is gone: no authenticated
    /// response for thirty seconds, or a 403 revoking it (RFC 7675 §5).
    ///
    /// Nothing more may be sent on that pair and the same credentials may not
    /// be used on it again. The remedy is an ICE restart, which draws new
    /// ones and checks every pair again
    /// ([`MediaEngine::restart_ice`](crate::MediaEngine::restart_ice)), or
    /// ending the call.
    #[cfg(feature = "ice")]
    IcePathLost,
    /// [`MediaEngine::restart_ice`](crate::MediaEngine::restart_ice) was
    /// asked of a call that runs no ICE agent: its catalogue offers no ICE,
    /// its peer answered without any, or its session has not opened yet.
    ///
    /// Nothing is sent. A restart is a new ICE session on a running one (RFC
    /// 8445 §9), and a call with none has nothing for new credentials to
    /// replace.
    #[cfg(feature = "ice")]
    NoIce,
    /// [`MediaEngine::readdress`](crate::MediaEngine::readdress) was asked
    /// of a call whose session runs ICE.
    ///
    /// Nothing is sent. Its candidates were gathered on the socket the call
    /// started on, so a description that moved only `c=` and `m=` would
    /// contradict every candidate line beside them (RFC 8839 §4.2.5): a call
    /// that runs ICE moves by a restart gathered on the new socket.
    #[cfg(feature = "ice")]
    MovesWithIce,
    /// The call asked for SRTP and would have carried audio without it: a
    /// plain offer arriving at a call set to [`SrtpPolicy::Required`], a
    /// plain re-offer inside one, a plain answer to its own offer, or an
    /// answer keyed the way its policy exists to avoid.
    ///
    /// The refusal is the point. Answering it plainly would be a silent
    /// downgrade, and there is no way for anyone on either end to notice one.
    /// The call is refused with it, not left to the application: an INVITE
    /// with 488 Not Acceptable Here (RFC 3261 §21.4.26), a re-offer the same
    /// way, and a call this end placed and the far end answered plainly
    /// with a BYE whose `Reason` says 488 (RFC 3326), once its 2xx has been
    /// acknowledged (§13.2.2.4).
    ///
    /// [`SrtpPolicy::Required`]: crate::SrtpPolicy::Required
    SrtpRequired,
    /// The description would carry an SDES key (`a=crypto` with `inline:`)
    /// over signalling that is not encrypted, and this call's catalogue says
    /// [`SdesSignalling::SecureOnly`](crate::SdesSignalling::SecureOnly)
    /// (RFC 4568 §8.3). Nothing was sent: a call placed was not placed, and
    /// a call being answered is still ringing for the application to reject.
    KeysWouldTravelInClear,
    /// A list of SRTP suites that names none, or names one twice
    /// ([`CodecCatalog::with_srtp_suites`](crate::CodecCatalog::with_srtp_suites)).
    NoSrtpSuite,
    /// The crypto line the negotiation settled on asks for something this
    /// build will not be held to: more than one master key on the line, one
    /// of RFC 4568 §6.3's session parameters that turns off encryption or
    /// authentication, a key derivation rate, or a parameter that has to be
    /// honoured and cannot be read.
    ///
    /// Refused rather than half-honoured: a stream opened on terms only one
    /// end believes produces packets the far end drops, which looks like a
    /// network fault for as long as somebody is willing to keep looking.
    UnusableKeying,
    /// The codec refused a frame. Opus is the only one that can, and it does
    /// so for a frame length it was not built for — so a build with the
    /// `opus` feature off has nothing that produces this and no variant for
    /// it.
    #[cfg(feature = "opus")]
    Codec(CodecError),
    /// The packet did not fit the buffer it had to be built in.
    PacketTooLong {
        /// What it needed.
        need: usize,
        /// What there was.
        got: usize,
    },
    /// A render-to-capture delay longer than anything between a loudspeaker
    /// and a microphone in the same room.
    ///
    /// Refused where it is set rather than turned into half a second of
    /// history per call: a number that large is a platform reporting
    /// something other than what was asked of it.
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
    /// A digit longer than any key is held: the same ceiling a digit sent or
    /// received by INFO is held to.
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
    /// A recording could not be started, or stopped writing part-way through.
    ///
    /// The kind rather than the error itself, because a call carries on when
    /// its recording fails and this has to be comparable and cloneable to
    /// travel in an event.
    Recording(std::io::ErrorKind),
    /// Nothing is being recorded on this call.
    NotRecording,
    /// A recording was asked for while one was already running. Two writers on
    /// one stream would interleave frames into both files.
    AlreadyRecording,
    /// A recording was asked for at a sampling rate its format cannot be
    /// written at: outside 8 to 48 kHz for WAV, or not one of Opus's five
    /// rates for Ogg Opus.
    RecordingRate {
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
    /// [`MediaEngine::join`](crate::MediaEngine::join) was asked to pair a
    /// call that is already paired with another.
    ///
    /// A call leaves the pair it is in
    /// ([`MediaEngine::leave`](crate::MediaEngine::leave)) before it joins
    /// another: two pairs sharing a call is a mix of three far ends and this
    /// end, which is not what this stack's own [`mix_two`](crate::mix_two)
    /// does the arithmetic for.
    AlreadyJoined,
    /// [`MediaEngine::leave`](crate::MediaEngine::leave) or
    /// [`MediaEngine::mix`](crate::MediaEngine::mix) was asked about a call
    /// that is not currently joined to another.
    NotJoined,
    /// [`MediaEngine::join`](crate::MediaEngine::join) was asked to pair two
    /// calls whose sessions decode at different sample rates, or cut audio
    /// into frames of different lengths.
    ///
    /// Nothing in [`mix_two`](crate::mix_two) resamples, so the samples it
    /// decodes out of one session have to line up, index for index, with the
    /// ones it decodes out of the other — which two codecs only agree on
    /// when they cut a frame the same way.
    JoinIncompatible,
    /// A [`LocalConference`](crate::LocalConference) has no place left, or
    /// was asked to be made with none or with more than
    /// [`MAX_CONFERENCE_MEMBERS`](crate::MAX_CONFERENCE_MEMBERS).
    ConferenceFull {
        /// How many members it holds, this end included.
        capacity: usize,
    },
    /// A call whose codec a [`LocalConference`](crate::LocalConference)
    /// cannot mix: it hears at a rate other than 8, 16, 32 or 48 kHz, or cuts
    /// frames longer than sixty milliseconds. A conference made for this end
    /// at such a rate is refused the same way, with no frame.
    ConferenceIncompatible {
        /// The rate asked for.
        hertz: u32,
        /// The frame asked for, in samples at that rate.
        frame_samples: usize,
    },
    /// The call is already in a [`LocalConference`](crate::LocalConference)
    /// or joined into a pair with
    /// [`MediaEngine::join`](crate::MediaEngine::join): two drivers of one
    /// call would each take every other frame from the other.
    InConference,
    /// A member was named that is not in the
    /// [`LocalConference`](crate::LocalConference): a call never added or
    /// already gone, or this end in a conference made without it.
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
    /// Text was asked for on a call that negotiated no real-time text stream
    /// (RFC 4103): it was given no text socket
    /// ([`CallMedia::text`](crate::CallMedia::text)), the far end refused or
    /// never offered one, or the call keys its audio.
    NoText,
    /// More text than the call holds unsent; none of it was queued.
    TextBufferFull {
        /// Characters there is still room for.
        room: usize,
    },
}

impl MediaError {
    /// The codec this build has no encoder for, when that is what went wrong.
    ///
    /// A caller reporting a failed call wants the name, and digging it out of
    /// the variant at every call site is how a log line ends up saying
    /// "media error".
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
    /// The sentence for a refusal about mixing calls — a pair or a local
    /// conference — which `Display` hands here for the reason it hands the
    /// path's to `about_the_path`.
    fn about_mixing(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::SameCall => f.write_str("a call cannot be joined to itself"),
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

    /// The refusals about how a call is secured and how its path is chosen.
    ///
    /// Lifted out of [`fmt::Display`] because the one match there had grown
    /// past what a reader holds at once, and because these are the group that
    /// travels together: every one of them is a call that could have carried
    /// audio and was not allowed to, and every one of them is one fixed
    /// sentence. `None` for everything else, which the match below still
    /// answers.
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

/// What a variant with no sentence of its own would print.
///
/// Nothing reaches it: [`MediaError::about_the_path`] answers for every arm
/// the match in [`fmt::Display`] does not, and
/// `every_media_error_says_something_of_its_own` is the test that keeps that
/// true as variants are added. It exists because a `Display` that panicked
/// would turn a log line into an abort.
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
            // every refusal about how a call is secured and how its path is
            // chosen, which `about_the_path` holds because the match here had
            // grown past what a reader holds at once
            other => f.write_str(other.about_the_path().unwrap_or(UNNAMED)),
        }
    }
}

impl core::error::Error for MediaError {}

#[cfg(test)]
mod tests {
    use super::{MediaError, UNNAMED};

    /// The dead branch, held dead.
    ///
    /// [`MediaError::about_the_path`] answers for every arm the match in
    /// `Display` does not, so `UNNAMED` can only be printed by a variant that
    /// was added to neither. This is what notices, rather than a caller
    /// reading a log line that explains nothing.
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
