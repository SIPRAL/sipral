// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Recording a call: both directions, one file, playable as it stands.
//!
//! Recording is neither protocol nor device, and putting it in either is how
//! it ends up half-implemented in both. It is a tap on the media path — the
//! frame that was decoded for the earpiece and the frame that went to the far
//! end — so it lives beside the pipeline that produces those two frames and
//! nowhere else.
//!
//! # What is written
//!
//! [`RecordingOptions`] chooses, and every choice is independent of the
//! codec the call is on: the file is written at its own rate, which is the
//! call's own unless another is named, and the two directions are converted
//! to it on the way in. That is also why a recording carries on through a
//! re-negotiation that moves the call to a codec at another rate — the file
//! does not move with it.
//!
//! - [`RecordingFormat::Wav`]: sixteen-bit PCM in RIFF/WAVE, the format every
//!   player on every platform opens, growing into RF64 past four gibibytes.
//! - `RecordingFormat::OggOpus`, where the `opus` feature is on: Opus in Ogg
//!   (RFC 7845), about a tenth of the size, with the encoder's own delay as
//!   the pre-skip and the stream's serial number drawn from the call's own
//!   randomness, so that two recordings chained into one file stay two
//!   streams.
//!
//! [`RecordingLayout::Mixed`] is one channel, the conversation as a listener
//! heard it; [`RecordingLayout::Stereo`] is two, **this end on the left and
//! the far end on the right**, which is what an analysis tool or a
//! transcription that attributes speech to a speaker wants.
//!
//! # Where a recording ends
//!
//! Stopped, the call ending, the stack being destroyed, or the recorder
//! being dropped for any other reason: all four finish the file the same
//! way — the WAVE header written with the real lengths, the last Ogg page
//! marked as the end of the stream and trimmed to the audio.
//!
//! What cannot be finished is a process that dies. For that there is the
//! checkpoint ([`RecordingOptions::checkpoint`], five seconds unless told
//! otherwise): a WAVE file's header is rewritten with the lengths reached so
//! far, and an Ogg stream's page is written out, so a crash leaves a file
//! that plays up to the last checkpoint. The WAVE file then holds the audio
//! after that point too, past the length its header states, where a player
//! does not look and an editor finds it; the Ogg stream simply ends at its
//! last whole page, without the page that marks the end.
//!
//! # Why the two directions are halved in a mixed file
//!
//! Two people talking at once, each at full scale, is louder than full scale.
//! Mixing at unity and letting the sum saturate distorts exactly the moments a
//! recording is usually kept for, and there is no way to undo it afterwards.
//! Halving each leg first means the sum reaches full scale only where both
//! directions are at full scale at the same instant, and never passes it; the
//! six decibels it costs are six decibels any player can put back.
//!
//! # Keeping the two directions level with each other
//!
//! Nothing guarantees that the application hands over a captured frame for
//! every played one. A muted microphone, a call on hold, a device that stalled
//! — any of them leaves one side arriving and the other not, and a mixer that
//! simply waited would stop writing and put the rest of the conversation at
//! the wrong time. So a direction that gets a second frame before the other
//! has produced its first is written against silence, and the file stays on
//! the call's own timeline.

use std::io::{Seek, Write};
use std::time::Duration;

#[cfg(feature = "opus")]
use sipral_media::formats::ogg_opus;
use sipral_media::formats::wav;
use sipral_media::mix::{Gain, sum_scaled_into};
#[cfg(feature = "opus")]
use sipral_media::opus;
use sipral_media::resample::Resampler;

use crate::error::MediaError;

/// Where a recording goes.
///
/// Write and seek, because the lengths in a WAVE header are only known when
/// the recording ends. `File` satisfies it, and so does `Cursor<Vec<u8>>`,
/// which is what the tests here record into. Nothing in this crate opens
/// either.
pub trait RecordingSink: Write + Seek + Send {}

impl<T: Write + Seek + Send> RecordingSink for T {}

/// The file format a recording is written in.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordingFormat {
    /// Sixteen-bit PCM in RIFF/WAVE, becoming RF64 past four gibibytes.
    #[default]
    Wav,
    /// Opus in Ogg (RFC 7845). Only where the `opus` feature is on: the
    /// encoder is libopus.
    #[cfg(feature = "opus")]
    OggOpus,
}

impl RecordingFormat {
    /// Ogg Opus, where this build has the encoder, and `None` where the
    /// `opus` feature is off.
    ///
    /// Asked of the value rather than of a `cfg`, for the reason
    /// [`Codec::is_opus`](crate::Codec::is_opus) is: a crate above this one
    /// cannot read this crate's features, and one that guessed from its own
    /// would offer a format this build cannot write.
    #[must_use]
    pub const fn ogg_opus() -> Option<Self> {
        #[cfg(feature = "opus")]
        {
            Some(Self::OggOpus)
        }
        #[cfg(not(feature = "opus"))]
        {
            None
        }
    }
}

/// How the two directions of a call share the file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecordingLayout {
    /// One channel: both directions, each at half level, summed.
    #[default]
    Mixed,
    /// Two channels: this end on the left, the far end on the right.
    Stereo,
}

/// How a recording is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RecordingOptions {
    /// The file format.
    pub format: RecordingFormat,
    /// One channel or two.
    pub layout: RecordingLayout,
    /// The rate the file is written at, in hertz, or `None` for the rate
    /// the call's codec hears at when the recording starts — or, for Ogg
    /// Opus on a call at a rate Opus does not take, 48 kHz. WAV takes any
    /// rate from 8 to 48 kHz; Ogg Opus takes Opus's five: 8, 12, 16, 24 and
    /// 48 kHz.
    pub sample_rate: Option<u32>,
    /// The bitrate an Ogg Opus recording is encoded at, in bits a second
    /// for all its channels together, or `None` for the one libopus picks
    /// for the rate. Ignored for WAV.
    pub bitrate: Option<u32>,
    /// How often what has been written is made to survive a crash; zero
    /// only at the end. See the module documentation.
    pub checkpoint: Duration,
}

impl Default for RecordingOptions {
    /// Mixed WAV at the call's rate, checkpointed every five seconds.
    fn default() -> Self {
        Self {
            format: RecordingFormat::Wav,
            layout: RecordingLayout::Mixed,
            sample_rate: None,
            bitrate: None,
            checkpoint: Duration::from_secs(5),
        }
    }
}

impl RecordingOptions {
    /// The rate a call at `call_rate` would be recorded at under these
    /// options.
    ///
    /// # Errors
    /// [`MediaError::RecordingRate`] for a rate the format cannot be written
    /// at, and [`MediaError::RecordingBitrate`] for a bitrate Opus is not
    /// defined at.
    pub fn rate_for(&self, call_rate: u32) -> Result<u32, MediaError> {
        match self.format {
            RecordingFormat::Wav => {
                let rate = self.sample_rate.unwrap_or(call_rate);
                if !(8_000..=48_000).contains(&rate) {
                    return Err(MediaError::RecordingRate { hertz: rate });
                }
                Ok(rate)
            }
            #[cfg(feature = "opus")]
            RecordingFormat::OggOpus => {
                if let Some(bits_per_second) = self.bitrate
                    && !(opus::MIN_BITRATE..=opus::MAX_BITRATE).contains(&bits_per_second)
                {
                    return Err(MediaError::RecordingBitrate { bits_per_second });
                }
                match self.sample_rate {
                    Some(hertz) => opus::SampleRate::from_hertz(hertz)
                        .map(opus::SampleRate::hertz)
                        .map_err(|_| MediaError::RecordingRate { hertz }),
                    None => Ok(opus::SampleRate::from_hertz(call_rate)
                        .map_or(opus::CLOCK_RATE, opus::SampleRate::hertz)),
                }
            }
        }
    }

    /// How many channels the Opus encoder is built with.
    #[cfg(feature = "opus")]
    const fn channels(&self) -> usize {
        match self.layout {
            RecordingLayout::Mixed => 1,
            RecordingLayout::Stereo => 2,
        }
    }
}

/// Which direction a frame came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leg {
    /// Towards the far end: what the microphone produced.
    Captured,
    /// From the far end: what the earpiece played.
    Played,
}

/// The file being written.
enum Writer {
    Wav(wav::Writer<Box<dyn RecordingSink>>),
    #[cfg(feature = "opus")]
    Opus(Box<OpusFile>),
}

/// An Ogg Opus stream, and the encoder feeding it twenty milliseconds at a
/// time.
#[cfg(feature = "opus")]
struct OpusFile {
    writer: ogg_opus::Writer<Box<dyn RecordingSink>>,
    encoder: opus::Encoder,
    /// Interleaved samples waiting for a whole frame.
    queued: Vec<i16>,
    packet: Vec<u8>,
    /// Samples per channel handed over so far, which is what the last page
    /// is trimmed to.
    taken: u64,
    /// And those encoded, the silence that flushes the encoder included.
    encoded: u64,
    rate: u32,
    channels: usize,
}

#[cfg(feature = "opus")]
impl OpusFile {
    /// The packet length, at 48 kHz: twenty milliseconds.
    const FRAME: opus::FrameDuration = opus::FrameDuration::Micros20000;

    fn start(
        sink: Box<dyn RecordingSink>,
        rate: u32,
        channels: usize,
        bitrate: Option<u32>,
        serial: u32,
    ) -> Result<Self, MediaError> {
        let opus_rate = opus::SampleRate::from_hertz(rate)?;
        let mut encoder = if channels == 2 {
            opus::Encoder::stereo(opus_rate, Self::FRAME)?
        } else {
            opus::Encoder::new(opus_rate, Self::FRAME)?
        };
        if let Some(bits) = bitrate {
            encoder.set_bitrate(bits)?;
        }
        let head = ogg_opus::OpusHead::new(
            if channels == 2 {
                ogg_opus::Channels::Stereo
            } else {
                ogg_opus::Channels::Mono
            },
            encoder.pre_skip()?,
            rate,
        );
        let writer = ogg_opus::Writer::new(sink, &head, &ogg_opus::OpusTags::new(), serial)
            .map_err(ogg_failed)?;
        Ok(Self {
            writer,
            queued: Vec::with_capacity(encoder.frame_samples() * channels * 2),
            packet: vec![0; Self::FRAME.max_packet_bytes()],
            encoder,
            taken: 0,
            encoded: 0,
            rate,
            channels,
        })
    }

    fn write(&mut self, interleaved: &[i16]) -> Result<(), MediaError> {
        self.queued.extend_from_slice(interleaved);
        self.taken = self
            .taken
            .saturating_add(u64::try_from(interleaved.len() / self.channels).unwrap_or(0));
        let whole = self.encoder.frame_samples() * self.channels;
        while self.queued.len() >= whole {
            self.encode(whole)?;
        }
        Ok(())
    }

    fn encode(&mut self, whole: usize) -> Result<(), MediaError> {
        let frame = self.queued.get(..whole).unwrap_or_default();
        let length = self.encoder.encode(frame, &mut self.packet)?;
        self.writer
            .write_packet(
                self.packet.get(..length).unwrap_or_default(),
                Self::FRAME.timestamp_increment(),
            )
            .map_err(ogg_failed)?;
        self.queued.drain(..whole);
        self.encoded = self
            .encoded
            .saturating_add(u64::try_from(whole / self.channels).unwrap_or(0));
        Ok(())
    }

    fn checkpoint(&mut self) -> Result<(), MediaError> {
        self.writer.flush().map_err(ogg_failed)
    }

    /// Encode what is left, and then silence until the encoder has given up
    /// the last of the audio, and end the stream at the audio's real length.
    ///
    /// The encoder runs its lookahead behind its input, so the last
    /// `lookahead` samples handed over come out only once that much more has
    /// gone in: a stream ended at the last whole frame would be short of its
    /// own end by the pre-skip, and the last page could not be trimmed to it
    /// (RFC 7845 §4.4 counts the pre-skip into the final granule position).
    fn finish(mut self) -> Result<(), MediaError> {
        let whole = self.encoder.frame_samples() * self.channels;
        let target = self
            .taken
            .saturating_add(u64::from(self.encoder.lookahead()?));
        while self.encoded < target {
            self.queued.resize(whole, 0);
            self.encode(whole)?;
        }
        let length =
            self.taken.saturating_mul(u64::from(opus::CLOCK_RATE)) / u64::from(self.rate.max(1));
        self.writer.finish(Some(length)).map_err(ogg_failed)?;
        Ok(())
    }
}

/// What the WAVE writer said, in the terms a call's recording reports.
fn wav_failed(error: wav::Error) -> MediaError {
    match error {
        wav::Error::Io(error) => MediaError::from(error),
        _ => MediaError::Recording(std::io::ErrorKind::InvalidInput),
    }
}

/// And the Ogg writer.
#[cfg(feature = "opus")]
fn ogg_failed(error: ogg_opus::Error) -> MediaError {
    match error {
        ogg_opus::Error::Io(error) => MediaError::from(error),
        _ => MediaError::Recording(std::io::ErrorKind::InvalidInput),
    }
}

/// One call being written to one file.
pub(crate) struct Recorder {
    layout: RecordingLayout,
    /// The rate the file is written at.
    rate: u32,
    /// The rate frames arrive at: the call's codec's.
    heard_at: u32,
    /// The frame from one direction that is waiting for its opposite number.
    /// Only one at a time: a second one means the other direction has stopped
    /// producing, and waiting any longer would bend the timeline.
    pending: Option<(Leg, Vec<i16>)>,
    /// Each direction from the call's rate to the file's, when they differ.
    /// Two, fed the same lengths, so they give the same lengths back.
    convert: Option<(Resampler, Resampler)>,
    silence: Vec<i16>,
    local: Vec<i16>,
    remote: Vec<i16>,
    /// The sum or the interleaving, reused so that a recording allocates as
    /// it starts rather than per frame.
    out: Vec<i16>,
    writer: Option<Writer>,
    /// Samples per channel written so far, at the file's rate.
    written: u64,
    /// And since the last checkpoint.
    since_checkpoint: u64,
    checkpoint_every: u64,
}

impl Recorder {
    /// Start a recording of a call at `heard_at` hertz, writing the header
    /// straight away. `serial` is the Ogg stream's serial number.
    ///
    /// # Errors
    /// Those of [`RecordingOptions::rate_for`], and whatever the sink says:
    /// a recording that cannot start says so here, and the call carries on.
    pub(crate) fn start(
        sink: Box<dyn RecordingSink>,
        options: &RecordingOptions,
        heard_at: u32,
        serial: u32,
    ) -> Result<Self, MediaError> {
        let rate = options.rate_for(heard_at)?;
        #[cfg(not(feature = "opus"))]
        let _ = serial;
        let writer = match options.format {
            RecordingFormat::Wav => {
                let channels = match options.layout {
                    RecordingLayout::Mixed => wav::Channels::Mono,
                    RecordingLayout::Stereo => wav::Channels::Stereo,
                };
                let mut sink = sink;
                sink.rewind()?;
                Writer::Wav(wav::Writer::new(sink, rate, channels).map_err(wav_failed)?)
            }
            #[cfg(feature = "opus")]
            RecordingFormat::OggOpus => Writer::Opus(Box::new(OpusFile::start(
                sink,
                rate,
                options.channels(),
                options.bitrate,
                serial,
            )?)),
        };
        let checkpoint = u64::try_from(options.checkpoint.as_millis()).unwrap_or(u64::MAX);
        Ok(Self {
            layout: options.layout,
            rate,
            heard_at,
            pending: None,
            convert: converters(heard_at, rate)?,
            silence: Vec::new(),
            local: Vec::new(),
            remote: Vec::new(),
            out: Vec::new(),
            writer: Some(writer),
            written: 0,
            since_checkpoint: 0,
            checkpoint_every: checkpoint.saturating_mul(u64::from(rate)) / 1_000,
        })
    }

    /// A frame that went to the far end.
    ///
    /// # Errors
    /// Whatever the sink says.
    pub(crate) fn captured(&mut self, samples: &[i16]) -> Result<(), MediaError> {
        self.offer(Leg::Captured, samples)
    }

    /// A frame handed to the earpiece.
    ///
    /// # Errors
    /// Whatever the sink says.
    pub(crate) fn played(&mut self, samples: &[i16]) -> Result<(), MediaError> {
        self.offer(Leg::Played, samples)
    }

    /// How much audio has been written.
    pub(crate) fn recorded(&self) -> Duration {
        Duration::from_nanos(
            self.written.saturating_mul(1_000_000_000) / u64::from(self.rate.max(1)),
        )
    }

    /// The call moved to a codec that hears at `heard_at`: what one
    /// direction is holding is written at the old rate, and from here on
    /// both are converted from the new one. The file does not change.
    ///
    /// # Errors
    /// Whatever the sink says.
    pub(crate) fn reformat(&mut self, heard_at: u32) -> Result<(), MediaError> {
        if heard_at == self.heard_at {
            return Ok(());
        }
        self.flush_pending()?;
        self.convert = converters(heard_at, self.rate)?;
        self.heard_at = heard_at;
        Ok(())
    }

    /// Close the recording: flush what one direction is still holding,
    /// finish the file, and let the sink go.
    ///
    /// # Errors
    /// Whatever the sink says. A file that could not be finished holds the
    /// audio up to the last checkpoint that could be written.
    pub(crate) fn finish(mut self) -> Result<(), MediaError> {
        self.close()
    }

    fn close(&mut self) -> Result<(), MediaError> {
        let flushed = self.flush_pending();
        let finished = match self.writer.take() {
            Some(Writer::Wav(writer)) => writer.finish().map(drop).map_err(wav_failed),
            #[cfg(feature = "opus")]
            Some(Writer::Opus(file)) => file.finish(),
            None => Ok(()),
        };
        flushed.and(finished)
    }

    fn flush_pending(&mut self) -> Result<(), MediaError> {
        match self.pending.take() {
            Some((Leg::Captured, frame)) => self.write_pair(&frame, &[]),
            Some((Leg::Played, frame)) => self.write_pair(&[], &frame),
            None => Ok(()),
        }
    }

    /// Take one direction's frame, and write a pair as soon as there is
    /// something to pair it with — or as soon as it is clear there will not
    /// be.
    fn offer(&mut self, leg: Leg, samples: &[i16]) -> Result<(), MediaError> {
        match self.pending.take() {
            Some((held, frame)) if held != leg => match leg {
                Leg::Captured => self.write_pair(samples, &frame),
                Leg::Played => self.write_pair(&frame, samples),
            },
            Some((held, frame)) => {
                // the same direction twice: the other one has stopped
                // producing, so this frame's opposite number is silence
                match held {
                    Leg::Captured => self.write_pair(&frame, &[])?,
                    Leg::Played => self.write_pair(&[], &frame)?,
                }
                self.pending = Some((leg, samples.to_vec()));
                Ok(())
            }
            None => {
                self.pending = Some((leg, samples.to_vec()));
                Ok(())
            }
        }
    }

    /// One frame of each direction, either of them possibly missing, at the
    /// call's rate: converted to the file's, then summed or interleaved, and
    /// written.
    fn write_pair(&mut self, captured: &[i16], played: &[i16]) -> Result<(), MediaError> {
        let length = captured.len().max(played.len());
        self.silence.resize(length, 0);
        let captured = if captured.is_empty() {
            self.silence.get(..length).unwrap_or_default()
        } else {
            captured
        };
        let played = if played.is_empty() {
            self.silence.get(..length).unwrap_or_default()
        } else {
            played
        };
        let frames = match self.convert.as_mut() {
            None => {
                self.local.clear();
                self.local.extend_from_slice(captured);
                self.remote.clear();
                self.remote.extend_from_slice(played);
                length
            }
            Some((local, remote)) => {
                let room = local.output_capacity(length);
                self.local.resize(room, 0);
                self.remote.resize(room, 0);
                let left = local.process(captured, &mut self.local).unwrap_or(0);
                let right = remote.process(played, &mut self.remote).unwrap_or(0);
                left.min(right)
            }
        };
        let local = self.local.get(..frames).unwrap_or_default();
        let remote = self.remote.get(..frames).unwrap_or_default();
        self.out.clear();
        match self.layout {
            RecordingLayout::Mixed => {
                self.out.resize(frames, 0);
                let half = Gain::ratio(1, 2);
                sum_scaled_into(&mut self.out, &[local, remote], &[half, half]);
            }
            RecordingLayout::Stereo => {
                for (left, right) in local.iter().zip(remote) {
                    self.out.push(*left);
                    self.out.push(*right);
                }
            }
        }
        match self.writer.as_mut() {
            Some(Writer::Wav(writer)) => writer.write_interleaved(&self.out).map_err(wav_failed)?,
            #[cfg(feature = "opus")]
            Some(Writer::Opus(file)) => file.write(&self.out)?,
            None => return Ok(()),
        }
        let frames = u64::try_from(frames).unwrap_or(0);
        self.written = self.written.saturating_add(frames);
        self.since_checkpoint = self.since_checkpoint.saturating_add(frames);
        if self.checkpoint_every > 0 && self.since_checkpoint >= self.checkpoint_every {
            self.since_checkpoint = 0;
            match self.writer.as_mut() {
                Some(Writer::Wav(writer)) => writer.checkpoint().map_err(wav_failed)?,
                #[cfg(feature = "opus")]
                Some(Writer::Opus(file)) => file.checkpoint()?,
                None => {}
            }
        }
        Ok(())
    }
}

/// A recorder dropped without being finished — the session it belonged to
/// going away however it went — still finishes its file: a playable file is
/// never a repair job.
impl Drop for Recorder {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// The two converters from the call's rate to the file's, or none where the
/// two are the same.
fn converters(from: u32, to: u32) -> Result<Option<(Resampler, Resampler)>, MediaError> {
    if from == to {
        return Ok(None);
    }
    let build = || Resampler::new(from, to).map_err(|_| MediaError::RecordingRate { hertz: to });
    Ok(Some((build()?, build()?)))
}

impl core::fmt::Debug for Recorder {
    /// The sink is a trait object with nothing to say about itself, and the
    /// buffers are a call's worth of audio.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recorder")
            .field("layout", &self.layout)
            .field("rate", &self.rate)
            .field("written", &self.written)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Recorder, RecordingFormat, RecordingLayout, RecordingOptions};
    use crate::error::MediaError;
    use sipral_media::formats::wav::HEADER_LEN;
    use std::io::{Cursor, Result, Seek, SeekFrom, Write};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    /// A sink the test can still read after the recorder has been handed it.
    ///
    /// The recorder owns its sink — a file is not something to keep a second
    /// handle on — so a test that wants the bytes back keeps the buffer behind
    /// a lock and gives the recorder a handle to it.
    #[derive(Clone, Debug, Default)]
    pub(crate) struct Buffer(Arc<Mutex<Cursor<Vec<u8>>>>);

    impl Buffer {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// Everything written so far.
        pub(crate) fn contents(&self) -> Vec<u8> {
            self.0.lock().unwrap().get_ref().clone()
        }
    }

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> Result<usize> {
            self.0.lock().unwrap().write(buf)
        }

        fn flush(&mut self) -> Result<()> {
            self.0.lock().unwrap().flush()
        }
    }

    impl Seek for Buffer {
        fn seek(&mut self, to: SeekFrom) -> Result<u64> {
            self.0.lock().unwrap().seek(to)
        }
    }

    /// One of the little-endian fields of a WAVE header.
    pub(crate) fn field(wav: &[u8], at: usize, len: usize) -> u32 {
        let mut value = 0_u32;
        for (index, byte) in wav[at..at + len].iter().enumerate() {
            value |= u32::from(*byte) << (index * 8);
        }
        value
    }

    /// Where the `fmt ` chunk's fields and the data chunk's length sit in the
    /// header `sipral-media` writes: after a `JUNK` chunk kept for RF64.
    pub(crate) const CHANNELS_AT: usize = 58;
    pub(crate) const RATE_AT: usize = 60;
    pub(crate) const DATA_LENGTH_AT: usize = 76;

    fn samples_of(wav: &[u8]) -> Vec<i16> {
        wav[HEADER_LEN..]
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect()
    }

    /// Record what `feed` produces and give back the finished file.
    fn finish(options: &RecordingOptions, rate: u32, feed: impl FnOnce(&mut Recorder)) -> Vec<u8> {
        let buffer = Buffer::new();
        let mut recorder = Recorder::start(Box::new(buffer.clone()), options, rate, 7).unwrap();
        feed(&mut recorder);
        recorder.finish().unwrap();
        buffer.contents()
    }

    #[test]
    fn by_default_the_file_is_mono_sixteen_bit_pcm_at_the_codec_rate() {
        let wav = finish(&RecordingOptions::default(), 16_000, |recorder| {
            recorder.captured(&[1_000; 320]).unwrap();
            recorder.played(&[1_000; 320]).unwrap();
        });
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(field(&wav, CHANNELS_AT, 2), 1, "one channel");
        assert_eq!(
            field(&wav, RATE_AT, 4),
            16_000,
            "the rate the codec hears at"
        );
        assert_eq!(field(&wav, DATA_LENGTH_AT, 4), 640);
        assert_eq!(wav.len(), HEADER_LEN + 640);
    }

    /// Both directions in one file, and the loudest thing the two of them can
    /// produce between them landing on full scale rather than past it.
    #[test]
    fn the_two_directions_are_mixed_and_do_not_pass_full_scale() {
        let wav = finish(&RecordingOptions::default(), 8_000, |recorder| {
            recorder.captured(&[i16::MAX; 4]).unwrap();
            recorder.played(&[i16::MAX; 4]).unwrap();
            recorder.captured(&[16_000; 4]).unwrap();
            recorder.played(&[16_000; 4]).unwrap();
        });
        assert_eq!(
            samples_of(&wav),
            [
                i16::MAX,
                i16::MAX,
                i16::MAX,
                i16::MAX,
                16_000,
                16_000,
                16_000,
                16_000
            ]
        );
    }

    /// Stereo keeps the two apart: this end left, the far end right.
    #[test]
    fn stereo_puts_this_end_on_the_left_and_the_far_end_on_the_right() {
        let options = RecordingOptions {
            layout: RecordingLayout::Stereo,
            ..RecordingOptions::default()
        };
        let wav = finish(&options, 8_000, |recorder| {
            recorder.played(&[-5; 3]).unwrap();
            recorder.captured(&[9; 3]).unwrap();
        });
        assert_eq!(field(&wav, CHANNELS_AT, 2), 2);
        assert_eq!(samples_of(&wav), [9, -5, 9, -5, 9, -5]);
    }

    /// One direction that stops producing must not stop the file: the
    /// conversation stays on its own timeline, with silence where the missing
    /// side would have been.
    #[test]
    fn a_direction_that_stops_does_not_stop_the_recording() {
        let options = RecordingOptions {
            layout: RecordingLayout::Stereo,
            ..RecordingOptions::default()
        };
        let wav = finish(&options, 8_000, |recorder| {
            recorder.played(&[8_000; 2]).unwrap();
            recorder.played(&[8_000; 2]).unwrap();
            recorder.played(&[8_000; 2]).unwrap();
        });
        assert_eq!(
            samples_of(&wav),
            [0, 8_000, 0, 8_000, 0, 8_000, 0, 8_000, 0, 8_000, 0, 8_000]
        );
    }

    #[test]
    fn a_recording_with_nothing_in_it_is_still_a_valid_file() {
        let wav = finish(&RecordingOptions::default(), 8_000, |_| {});
        assert_eq!(wav.len(), HEADER_LEN);
        assert_eq!(field(&wav, DATA_LENGTH_AT, 4), 0);
        assert_eq!(usize::try_from(field(&wav, 4, 4)).unwrap(), HEADER_LEN - 8);
    }

    /// The file's rate is its own: a call at 8 kHz recorded at 16 kHz has
    /// twice as many samples, and a tone in it keeps its pitch.
    #[test]
    fn a_rate_other_than_the_calls_is_converted_to() {
        let options = RecordingOptions {
            sample_rate: Some(16_000),
            layout: RecordingLayout::Stereo,
            ..RecordingOptions::default()
        };
        // 500 Hz is a whole number of cycles in a frame at 8 kHz, so frames
        // repeat it seamlessly; at most 8000 either side of zero
        #[allow(clippy::cast_possible_truncation)]
        let tone: Vec<i16> = (0..160_u32)
            .map(|n| {
                (8_000.0 * (2.0 * std::f64::consts::PI * 500.0 * f64::from(n) / 8_000.0).sin())
                    .round() as i16
            })
            .collect();
        let wav = finish(&options, 8_000, |recorder| {
            for _ in 0..50 {
                recorder.captured(&tone).unwrap();
                recorder.played(&[0; 160]).unwrap();
            }
        });
        assert_eq!(field(&wav, RATE_AT, 4), 16_000);
        let samples = samples_of(&wav);
        let frames = samples.len() / 2;
        // a second of audio, less the converter's own delay: what it still
        // holds when the file ends
        let delay = sipral_media::resample::Resampler::new(8_000, 16_000)
            .unwrap()
            .latency_samples();
        assert!(
            frames.abs_diff(16_000 - delay) <= 2,
            "{frames} frames for a second, {delay} of them held by the converter"
        );
        let left: Vec<i16> = samples.iter().step_by(2).copied().collect();
        let crossings = left[1_000..]
            .windows(2)
            .filter(|pair| (pair[0] < 0) != (pair[1] < 0))
            .count();
        let expected = 2 * 500 * (left.len() - 1_000) / 16_000;
        assert!(
            crossings.abs_diff(expected) <= 3,
            "{crossings} against {expected}"
        );
        assert!(samples.iter().skip(1).step_by(2).all(|&right| right == 0));
    }

    /// A call that moves to a codec at another rate goes on into the same
    /// file, converted: the file's rate does not move with the codec.
    #[test]
    fn a_codec_change_that_moves_the_rate_carries_on_into_the_same_file() {
        let wav = finish(&RecordingOptions::default(), 8_000, |recorder| {
            recorder.captured(&[100; 160]).unwrap();
            recorder.played(&[100; 160]).unwrap();
            recorder.reformat(16_000).unwrap();
            for _ in 0..10 {
                recorder.captured(&[100; 320]).unwrap();
                recorder.played(&[100; 320]).unwrap();
            }
        });
        assert_eq!(field(&wav, RATE_AT, 4), 8_000, "the file kept its rate");
        let samples = samples_of(&wav).len();
        let delay = sipral_media::resample::Resampler::new(16_000, 8_000)
            .unwrap()
            .latency_samples();
        assert!(
            samples.abs_diff(11 * 160 - delay) <= 2,
            "{samples}, {delay} held by the converter"
        );
    }

    /// The checkpoint: a file whose process died mid-recording opens with
    /// what was written up to the last one.
    #[test]
    fn a_file_abandoned_mid_recording_states_what_it_held_at_the_last_checkpoint() {
        let buffer = Buffer::new();
        let options = RecordingOptions {
            checkpoint: Duration::from_millis(100),
            ..RecordingOptions::default()
        };
        let mut recorder = Recorder::start(Box::new(buffer.clone()), &options, 8_000, 1).unwrap();
        for _ in 0..12 {
            recorder.captured(&[1; 160]).unwrap();
            recorder.played(&[1; 160]).unwrap();
        }
        // what a crash leaves is what the sink holds now, before any finish
        let abandoned = buffer.contents();
        assert_eq!(
            field(&abandoned, DATA_LENGTH_AT, 4),
            10 * 160 * 2,
            "the header states the audio up to the last checkpoint"
        );
        assert_eq!(
            abandoned.len(),
            HEADER_LEN + 12 * 160 * 2,
            "and all of it is there"
        );
        std::mem::forget(recorder);
    }

    /// Dropped without being finished, a recorder finishes its file anyway.
    #[test]
    fn a_recorder_dropped_without_finishing_still_finishes_its_file() {
        let buffer = Buffer::new();
        let options = RecordingOptions {
            checkpoint: Duration::ZERO,
            ..RecordingOptions::default()
        };
        let mut recorder = Recorder::start(Box::new(buffer.clone()), &options, 8_000, 1).unwrap();
        for _ in 0..3 {
            recorder.captured(&[1; 160]).unwrap();
            recorder.played(&[1; 160]).unwrap();
        }
        assert_eq!(
            field(&buffer.contents(), DATA_LENGTH_AT, 4),
            0,
            "no checkpoint was asked for"
        );
        drop(recorder);
        assert_eq!(field(&buffer.contents(), DATA_LENGTH_AT, 4), 3 * 160 * 2);
    }

    #[test]
    fn a_rate_the_format_cannot_be_written_at_is_refused() {
        let options = RecordingOptions {
            sample_rate: Some(96_000),
            ..RecordingOptions::default()
        };
        assert_eq!(
            options.rate_for(8_000),
            Err(MediaError::RecordingRate { hertz: 96_000 })
        );
        assert!(Recorder::start(Box::new(Buffer::new()), &options, 8_000, 1).is_err());
        assert_eq!(RecordingOptions::default().rate_for(16_000), Ok(16_000));
        assert_eq!(RecordingFormat::default(), RecordingFormat::Wav);
    }

    #[cfg(feature = "opus")]
    mod ogg_opus {
        use super::{Buffer, Recorder, RecordingLayout, RecordingOptions};
        use crate::error::MediaError;
        use crate::record::RecordingFormat;
        use sipral_media::formats::ogg;
        use sipral_media::opus::{Decoder, Encoder, FrameDuration, SampleRate};

        fn opus(layout: RecordingLayout) -> RecordingOptions {
            RecordingOptions {
                format: RecordingFormat::OggOpus,
                layout,
                ..RecordingOptions::default()
            }
        }

        fn speech(n: u32, rate: u32) -> i16 {
            let t = f64::from(n) / f64::from(rate);
            // at most 6000 either side of zero
            #[allow(clippy::cast_possible_truncation)]
            let sample = (6_000.0 * (2.0 * std::f64::consts::PI * 220.0 * t).sin()).round() as i16;
            sample
        }

        /// The stream is what RFC 7845 asks, with the pre-skip the encoder
        /// really has, the serial the call drew, and a last page trimmed to
        /// exactly the audio that was recorded.
        #[test]
        fn an_ogg_opus_recording_carries_the_real_pre_skip_and_ends_at_the_audio() {
            let buffer = Buffer::new();
            let mut recorder = Recorder::start(
                Box::new(buffer.clone()),
                &opus(RecordingLayout::Stereo),
                16_000,
                0xdead_beef,
            )
            .unwrap();
            // 1.03 seconds: not a whole number of twenty-millisecond packets
            for frame in 0..103_u32 {
                let voice: Vec<i16> = (0..160).map(|n| speech(frame * 160 + n, 16_000)).collect();
                recorder.captured(&voice).unwrap();
                recorder.played(&[0; 160]).unwrap();
            }
            recorder.finish().unwrap();
            let bytes = buffer.contents();

            let packets = ogg::read_packets(&bytes).unwrap();
            let (page, _) = ogg::Page::parse(&bytes).unwrap();
            assert_eq!(page.serial(), 0xdead_beef);
            let head = &packets[0].data;
            assert_eq!(&head[..8], b"OpusHead");
            assert_eq!(head[9], 2, "two channels");
            let pre_skip = u16::from_le_bytes([head[10], head[11]]);
            let mut reference =
                Encoder::stereo(SampleRate::Wideband, FrameDuration::Micros20000).unwrap();
            assert_eq!(
                pre_skip,
                reference.pre_skip().unwrap(),
                "a guessed pre-skip"
            );
            assert_eq!(
                u32::from_le_bytes([head[12], head[13], head[14], head[15]]),
                16_000
            );
            let last = packets.last().unwrap();
            assert!(last.eos);
            assert_eq!(
                last.granule,
                Some(u64::from(pre_skip) + 103 * 10 * 48),
                "the last page is not trimmed to the audio"
            );
            // every audio packet decodes
            let mut decoder =
                Decoder::new(SampleRate::Wideband, FrameDuration::Micros20000).unwrap();
            let mut pcm = vec![0_i16; 320];
            for packet in &packets[2..] {
                assert_eq!(decoder.decode(&packet.data, &mut pcm).unwrap(), 320);
            }
            // 1.03 s and the encoder's delay behind it, in whole packets
            let lookahead = reference.lookahead().unwrap() as usize;
            assert_eq!(packets.len() - 2, (16_480 + lookahead).div_ceil(320));
        }

        /// A recording that ends on a whole packet still holds its last
        /// samples: the encoder is flushed past its delay, so the last page
        /// can be trimmed to exactly the audio.
        #[test]
        fn a_recording_that_ends_on_a_whole_packet_keeps_its_last_samples() {
            let buffer = Buffer::new();
            let mut recorder = Recorder::start(
                Box::new(buffer.clone()),
                &opus(RecordingLayout::Mixed),
                8_000,
                5,
            )
            .unwrap();
            for frame in 0..10_u32 {
                let voice: Vec<i16> = (0..160).map(|n| speech(frame * 160 + n, 8_000)).collect();
                recorder.captured(&voice).unwrap();
                recorder.played(&voice).unwrap();
            }
            recorder.finish().expect("the stream ends at the audio");
            let packets = ogg::read_packets(&buffer.contents()).unwrap();
            let head = &packets[0].data;
            let pre_skip = u64::from(u16::from_le_bytes([head[10], head[11]]));
            assert_eq!(packets.last().unwrap().granule, Some(pre_skip + 10 * 960));
        }

        /// A crash leaves the pages written so far, each whole: a checkpoint
        /// writes the page being filled.
        #[test]
        fn an_abandoned_ogg_opus_recording_holds_whole_pages_up_to_the_last_checkpoint() {
            let buffer = Buffer::new();
            let options = RecordingOptions {
                checkpoint: std::time::Duration::from_millis(200),
                ..opus(RecordingLayout::Mixed)
            };
            let mut recorder =
                Recorder::start(Box::new(buffer.clone()), &options, 8_000, 3).unwrap();
            for frame in 0..30_u32 {
                let voice: Vec<i16> = (0..160).map(|n| speech(frame * 160 + n, 8_000)).collect();
                recorder.captured(&voice).unwrap();
                recorder.played(&voice).unwrap();
            }
            let abandoned = buffer.contents();
            // whole pages to the last octet, none of them the end of the
            // stream, and the last one reaching past the last checkpoint
            let mut rest = abandoned.as_slice();
            let mut last_granule = 0;
            while !rest.is_empty() {
                let (page, length) = ogg::Page::parse(rest).unwrap();
                assert!(!page.is_eos());
                if page.granule() != ogg::NO_GRANULE {
                    last_granule = page.granule();
                }
                rest = &rest[length..];
            }
            // 600 ms were handed over, the last of them with a checkpoint,
            // which wrote out everything encoded by then but the one packet
            // held back for trimming the end
            assert!(last_granule >= 580 * 48, "the pages reach {last_granule}");
            std::mem::forget(recorder);
        }

        #[test]
        fn ogg_opus_takes_opus_rates_and_bitrates_only() {
            let at = |hertz| RecordingOptions {
                sample_rate: Some(hertz),
                ..opus(RecordingLayout::Mixed)
            };
            assert_eq!(
                at(44_100).rate_for(8_000),
                Err(MediaError::RecordingRate { hertz: 44_100 })
            );
            assert_eq!(at(24_000).rate_for(8_000), Ok(24_000));
            assert_eq!(opus(RecordingLayout::Mixed).rate_for(22_050), Ok(48_000));
            let bitrate = RecordingOptions {
                bitrate: Some(1_000),
                ..opus(RecordingLayout::Mixed)
            };
            assert_eq!(
                bitrate.rate_for(8_000),
                Err(MediaError::RecordingBitrate {
                    bits_per_second: 1_000
                })
            );
        }
    }
}
