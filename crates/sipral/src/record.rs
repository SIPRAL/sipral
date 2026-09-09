// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Recording a call: both directions, one file, playable as it stands.
//!
//! Recording is neither protocol nor device, and putting it in either is how
//! it ends up half-implemented in both. It is a tap on the media path — the
//! frame that was decoded for the earpiece and the frame that was taken from
//! the microphone, mixed and written — so it lives beside the pipeline that
//! produces those two frames and nowhere else.
//!
//! # What is written
//!
//! RIFF/WAVE, linear 16-bit PCM, one channel, at the rate the codec of the
//! call hears at. That is the format every player on every platform opens
//! without being asked to convert anything, and it is the reason the file is
//! not the encoded stream: a recording of G.722 payloads is a recording nobody
//! can play, and one of Opus payloads is a container problem.
//!
//! The header carries two lengths that are not known until the recording
//! stops, which is why the sink has to seek: they are written as zero at the
//! start and patched at the end. A file whose recording was interrupted — the
//! process died, the disk filled — therefore has zeroes in those two fields.
//! That is a deliberate trade against the alternative of buffering the call in
//! memory, and it is recoverable: the audio is all there and any editor will
//! repair the header.
//!
//! # Why the two directions are halved
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

use std::io::{Seek, SeekFrom, Write};

use sipral_media::mix::{Gain, sum_scaled_into};

/// Where a recording goes.
///
/// Write and seek, because the two lengths in a WAVE header are only known
/// when the recording ends. `File` satisfies it, and so does
/// `Cursor<Vec<u8>>`, which is what the tests here record into. Nothing in
/// this crate opens either.
pub trait RecordingSink: Write + Seek + Send {}

impl<T: Write + Seek + Send> RecordingSink for T {}

/// Octets of header before the first sample: the RIFF chunk, the format chunk
/// and the data chunk's own header.
const HEADER_LEN: usize = 44;

/// Where the RIFF chunk's length field sits.
const RIFF_LENGTH_AT: u64 = 4;

/// Where the data chunk's length field sits.
const DATA_LENGTH_AT: u64 = 40;

/// One call being written to one file.
pub(crate) struct Recorder {
    sink: Box<dyn RecordingSink>,
    /// Samples written so far, which is what both length fields are computed
    /// from at the end.
    samples: u64,
    /// The frame from one direction that is waiting for its opposite number.
    /// Only one at a time: a second one means the other direction has stopped
    /// producing, and waiting any longer would bend the timeline.
    pending: Option<(Leg, Vec<i16>)>,
    /// Reused for the sum, so that a recording allocates once rather than per
    /// frame.
    mixed: Vec<i16>,
    /// Reused for the octets of one frame, for the same reason.
    octets: Vec<u8>,
}

/// Which direction a frame came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leg {
    /// Towards the far end: what the microphone produced.
    Captured,
    /// From the far end: what the earpiece played.
    Played,
}

impl Recorder {
    /// Start a recording, writing the header straight away.
    ///
    /// # Errors
    /// Whatever the sink says. A recording that cannot start says so here, and
    /// the call carries on.
    pub(crate) fn start(
        mut sink: Box<dyn RecordingSink>,
        sample_rate: u32,
        frame_samples: usize,
    ) -> std::io::Result<Self> {
        sink.rewind()?;
        sink.write_all(&header(sample_rate))?;
        Ok(Self {
            sink,
            samples: 0,
            pending: None,
            mixed: vec![0; frame_samples],
            octets: vec![0; frame_samples.saturating_mul(2)],
        })
    }

    /// A frame taken from the microphone.
    ///
    /// # Errors
    /// Whatever the sink says.
    pub(crate) fn captured(&mut self, samples: &[i16]) -> std::io::Result<()> {
        self.offer(Leg::Captured, samples)
    }

    /// A frame handed to the earpiece.
    ///
    /// # Errors
    /// Whatever the sink says.
    pub(crate) fn played(&mut self, samples: &[i16]) -> std::io::Result<()> {
        self.offer(Leg::Played, samples)
    }

    /// How much audio has been written, in samples.
    pub(crate) const fn written(&self) -> u64 {
        self.samples
    }

    /// Close the recording: flush what one direction is still holding, patch
    /// the two lengths, and let the sink go.
    ///
    /// # Errors
    /// Whatever the sink says. A header that could not be patched leaves a
    /// file with the audio in it and zeroes in the two length fields.
    pub(crate) fn finish(mut self) -> std::io::Result<()> {
        if let Some((_, frame)) = self.pending.take() {
            self.write_mixed(&frame, &[])?;
        }
        let audio = usize::try_from(self.samples)
            .unwrap_or(usize::MAX)
            .saturating_mul(2);
        self.sink.seek(SeekFrom::Start(RIFF_LENGTH_AT))?;
        let riff =
            u32::try_from(HEADER_LEN.saturating_sub(8).saturating_add(audio)).unwrap_or(u32::MAX);
        self.sink.write_all(&riff.to_le_bytes())?;
        self.sink.seek(SeekFrom::Start(DATA_LENGTH_AT))?;
        let data = u32::try_from(audio).unwrap_or(u32::MAX);
        self.sink.write_all(&data.to_le_bytes())?;
        self.sink.flush()
    }

    /// Take one direction's frame, and write a mixed one as soon as there is
    /// something to mix it with — or as soon as it is clear there will not be.
    fn offer(&mut self, leg: Leg, samples: &[i16]) -> std::io::Result<()> {
        match self.pending.take() {
            Some((held, frame)) if held != leg => match leg {
                Leg::Captured => self.write_mixed(samples, &frame),
                Leg::Played => self.write_mixed(&frame, samples),
            },
            Some((held, frame)) => {
                // the same direction twice: the other one has stopped
                // producing, so this frame's opposite number is silence
                match held {
                    Leg::Captured => self.write_mixed(&frame, &[])?,
                    Leg::Played => self.write_mixed(&[], &frame)?,
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

    /// Sum the two directions, each at half scale, and put the result on the
    /// sink as little-endian sixteen-bit samples.
    fn write_mixed(&mut self, captured: &[i16], played: &[i16]) -> std::io::Result<()> {
        let length = captured.len().max(played.len());
        self.mixed.resize(length, 0);
        let half = Gain::ratio(1, 2);
        sum_scaled_into(&mut self.mixed, &[captured, played], &[half, half]);

        self.octets.clear();
        for sample in &self.mixed {
            self.octets.extend_from_slice(&sample.to_le_bytes());
        }
        self.sink.write_all(&self.octets)?;
        self.samples = self
            .samples
            .saturating_add(u64::try_from(length).unwrap_or(u64::MAX));
        Ok(())
    }
}

impl core::fmt::Debug for Recorder {
    /// The sink is a trait object with nothing to say about itself, and the
    /// three buffers are a call's worth of audio.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Recorder")
            .field("samples", &self.samples)
            .finish_non_exhaustive()
    }
}

/// The forty-four octets in front of the audio: a RIFF chunk naming WAVE, a
/// format chunk saying uncompressed sixteen-bit mono, and the header of the
/// data chunk.
///
/// The two lengths are zero here and are patched when the recording stops.
fn header(sample_rate: u32) -> [u8; HEADER_LEN] {
    /// Uncompressed PCM, which is format 1 in the WAVE format tag registry.
    const PCM: u16 = 1;
    /// One channel. Both directions of a call are one conversation, and a
    /// listener wants to hear it rather than to pan it.
    const CHANNELS: u16 = 1;
    /// Two octets a sample.
    const BLOCK_ALIGN: u16 = 2;
    /// Sixteen bits of them.
    const BITS: u16 = 16;

    let mut out = [0_u8; HEADER_LEN];
    let mut at = 0;
    let mut put = |bytes: &[u8]| {
        if let Some(room) = out.get_mut(at..at + bytes.len()) {
            room.copy_from_slice(bytes);
        }
        at += bytes.len();
    };
    put(b"RIFF");
    put(&0_u32.to_le_bytes());
    put(b"WAVE");
    put(b"fmt ");
    put(&16_u32.to_le_bytes());
    put(&PCM.to_le_bytes());
    put(&CHANNELS.to_le_bytes());
    put(&sample_rate.to_le_bytes());
    put(&sample_rate
        .saturating_mul(u32::from(BLOCK_ALIGN))
        .to_le_bytes());
    put(&BLOCK_ALIGN.to_le_bytes());
    put(&BITS.to_le_bytes());
    put(b"data");
    put(&0_u32.to_le_bytes());
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{HEADER_LEN, Recorder};
    use std::io::{Cursor, Result, Seek, SeekFrom, Write};
    use std::sync::{Arc, Mutex};

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
    fn field(wav: &[u8], at: usize, len: usize) -> u32 {
        let mut value = 0_u32;
        for (index, byte) in wav[at..at + len].iter().enumerate() {
            value |= u32::from(*byte) << (index * 8);
        }
        value
    }

    /// Record what `feed` produces and give back the finished file.
    fn finish(rate: u32, frame: usize, feed: impl FnOnce(&mut Recorder)) -> Vec<u8> {
        let buffer = Buffer::new();
        let mut recorder = Recorder::start(Box::new(buffer.clone()), rate, frame).unwrap();
        feed(&mut recorder);
        recorder.finish().unwrap();
        buffer.contents()
    }

    #[test]
    fn the_header_says_mono_sixteen_bit_pcm_at_the_codec_rate() {
        let wav = finish(16_000, 320, |recorder| {
            recorder.captured(&[1_000; 320]).unwrap();
            recorder.played(&[1_000; 320]).unwrap();
        });
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(&wav[12..16], b"fmt ");
        assert_eq!(field(&wav, 16, 4), 16, "the format chunk is sixteen octets");
        assert_eq!(field(&wav, 20, 2), 1, "uncompressed PCM");
        assert_eq!(field(&wav, 22, 2), 1, "one channel");
        assert_eq!(field(&wav, 24, 4), 16_000, "the rate the codec hears at");
        assert_eq!(
            field(&wav, 28, 4),
            32_000,
            "two octets a sample, per second"
        );
        assert_eq!(field(&wav, 32, 2), 2, "block align");
        assert_eq!(field(&wav, 34, 2), 16, "sixteen bits");
        assert_eq!(&wav[36..40], b"data");
    }

    /// The two lengths are what decides whether a player opens the file or
    /// says it is corrupt, and they are only right if they were patched.
    #[test]
    fn the_two_lengths_are_patched_when_the_recording_stops() {
        let wav = finish(8_000, 160, |recorder| {
            for _ in 0..3 {
                recorder.captured(&[100; 160]).unwrap();
                recorder.played(&[100; 160]).unwrap();
            }
        });
        let audio = 3 * 160 * 2;
        assert_eq!(wav.len(), HEADER_LEN + audio);
        assert_eq!(
            usize::try_from(field(&wav, 4, 4)).unwrap(),
            HEADER_LEN - 8 + audio
        );
        assert_eq!(usize::try_from(field(&wav, 40, 4)).unwrap(), audio);
    }

    /// Both directions in one file, and the loudest thing the two of them can
    /// produce between them landing on full scale rather than past it.
    #[test]
    fn the_two_directions_are_mixed_and_do_not_pass_full_scale() {
        let wav = finish(8_000, 4, |recorder| {
            recorder.captured(&[i16::MAX; 4]).unwrap();
            recorder.played(&[i16::MAX; 4]).unwrap();
        });
        let samples: Vec<i16> = wav[HEADER_LEN..]
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(samples.len(), 4);
        for sample in samples {
            // two full-scale legs, halved and added: full scale, and a sum
            // that wrapped instead of saturating would read as loud silence
            assert_eq!(sample, i16::MAX);
        }
    }

    /// Each direction arrives at half its own level, which is the thing that
    /// makes the test above pass for the right reason. Two legs at half scale
    /// have to come back at half scale; a mixer that added them at unity would
    /// read twice this, and would only be caught by the clipping it causes on
    /// the next loud syllable rather than here.
    #[test]
    fn each_direction_arrives_at_half_its_own_level() {
        let wav = finish(8_000, 4, |recorder| {
            recorder.captured(&[16_000; 4]).unwrap();
            recorder.played(&[16_000; 4]).unwrap();
        });
        let samples: Vec<i16> = wav[HEADER_LEN..]
            .chunks_exact(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        assert_eq!(samples, [16_000; 4]);
    }

    /// One direction that stops producing must not stop the file: the
    /// conversation stays on its own timeline, with silence where the missing
    /// side would have been.
    #[test]
    fn a_direction_that_stops_does_not_stop_the_recording() {
        let wav = finish(8_000, 2, |recorder| {
            recorder.played(&[8_000; 2]).unwrap();
            recorder.played(&[8_000; 2]).unwrap();
            recorder.played(&[8_000; 2]).unwrap();
        });
        let samples = (wav.len() - HEADER_LEN) / 2;
        assert_eq!(samples, 6, "three frames of two samples, all of them kept");
    }

    #[test]
    fn a_recording_with_nothing_in_it_is_still_a_valid_file() {
        let wav = finish(8_000, 160, |_| {});
        assert_eq!(wav.len(), HEADER_LEN);
        assert_eq!(field(&wav, 40, 4), 0);
        assert_eq!(usize::try_from(field(&wav, 4, 4)).unwrap(), HEADER_LEN - 8);
    }
}
