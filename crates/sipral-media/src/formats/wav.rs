// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Sixteen-bit PCM in RIFF/WAVE, written as it arrives, and RF64 when it
//! outgrows RIFF.
//!
//! A call recording is two sides, and [`Writer::write_stereo`] puts them in
//! one file: **the left channel is the local side, the right channel is the
//! remote side**. A player shows one speaker per ear, and an analysis tool
//! gets each side without having to separate them. A mono file, one mix of
//! both, is written the same way with [`Channels::Mono`].
//!
//! # Layout
//!
//! Every file this writes has the same 80-octet header: the `RIFF` chunk
//! header and `WAVE`, a 28-octet chunk that is `JUNK` for now, the 16-octet
//! `fmt ` chunk for integer PCM, and the `data` chunk header; the samples
//! follow, little-endian and interleaved one frame at a time. The sizes in
//! the header are not known until the end, so [`Writer::finish`] seeks back
//! and writes them.
//!
//! # Four gibibytes
//!
//! RIFF's chunk sizes are 32 bits, which stops a file at four gibibytes: six
//! hours and a quarter of 48 kHz stereo, which a recorded conference line
//! can reach. Past that point the writer does not stop. It finishes the file
//! as RF64 instead, the extension of EBU Tech 3306 made for exactly this:
//! the `RIFF` identifier becomes `RF64`, the `JUNK` chunk that was reserved
//! for it becomes `ds64` and carries the 64-bit RIFF size, data size and
//! sample count, and the two 32-bit sizes it replaces are set to all ones.
//! A file that stayed under the limit stays a plain WAV file that every
//! reader opens, with a `JUNK` chunk in it that every reader skips.
//!
//! The switch happens when the RIFF size, everything after its own size
//! field, would no longer fit below 0xFFFFFFFF, which RF64 reserves as its
//! "see ds64" marker. [`Form::for_data`] is that decision on its own.

use core::fmt;
use std::io::{self, Seek, SeekFrom, Write};

/// The length of the header this writes, in octets.
pub const HEADER_LEN: usize = 80;

/// The bits in one sample.
pub const BITS_PER_SAMPLE: u16 = 16;

/// The `fmt ` chunk's format tag for integer PCM.
pub const FORMAT_PCM: u16 = 1;

/// The largest data size a plain RIFF file carries. The RIFF size is the
/// data plus the 72 header octets after the RIFF size field, and has to
/// stay below 0xFFFFFFFF.
pub const MAX_RIFF_DATA: u64 = 0xFFFF_FFFE - (HEADER_LEN as u64 - 8);

/// The size RF64 writes into a 32-bit field whose real value is in `ds64`.
const SEE_DS64: u32 = u32::MAX;

/// The length of the `ds64` chunk body with no table: three 64-bit sizes and
/// a 32-bit table length.
const DS64_LEN: u32 = 28;

/// Which of the two forms a file is finished in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Form {
    /// A plain RIFF/WAVE file.
    Riff,
    /// An RF64 file, EBU Tech 3306.
    Rf64,
}

impl Form {
    /// The form a file with `data_bytes` of samples is finished in.
    #[must_use]
    pub const fn for_data(data_bytes: u64) -> Self {
        if data_bytes <= MAX_RIFF_DATA {
            Self::Riff
        } else {
            Self::Rf64
        }
    }
}

/// How many channels a file carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channels {
    /// One channel.
    Mono,
    /// Two: left is the local side, right the remote side.
    Stereo,
}

impl Channels {
    /// The channel count the `fmt ` chunk carries.
    #[must_use]
    pub const fn count(self) -> u16 {
        match self {
            Self::Mono => 1,
            Self::Stereo => 2,
        }
    }

    /// The octets in one frame: one sample of each channel.
    #[must_use]
    pub const fn block_align(self) -> u16 {
        self.count() * (BITS_PER_SAMPLE / 8)
    }
}

/// Why the [`Writer`] refused.
#[derive(Debug)]
pub enum Error {
    /// The sink failed.
    Io(io::Error),
    /// A sampling rate of zero, or one so high that the byte rate does not
    /// fit the `fmt ` chunk's 32 bits.
    Rate(u32),
    /// Interleaved samples that do not make whole frames.
    PartialFrame {
        /// How many samples were given.
        samples: usize,
    },
    /// The two sides handed to [`Writer::write_stereo`] differ in length.
    Lengths {
        /// Samples of the local side.
        local: usize,
        /// Samples of the remote side.
        remote: usize,
    },
    /// [`Writer::write_stereo`] on a mono file.
    NotStereo,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "writing the WAV file failed: {error}"),
            Self::Rate(rate) => write!(f, "{rate} Hz cannot be written in a WAV header"),
            Self::PartialFrame { samples } => {
                write!(f, "{samples} interleaved samples are not whole frames")
            }
            Self::Lengths { local, remote } => write!(
                f,
                "{local} local samples and {remote} remote samples do not make frames"
            ),
            Self::NotStereo => f.write_str("two sides written to a mono file"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// The header for a file of `data_bytes` of samples at `rate` hertz, in the
/// form [`Form::for_data`] picks.
///
/// # Errors
///
/// [`Error::Rate`] for a rate of zero or one whose byte rate overflows.
pub fn header(rate: u32, channels: Channels, data_bytes: u64) -> Result<[u8; HEADER_LEN], Error> {
    let byte_rate = byte_rate(rate, channels)?;
    let form = Form::for_data(data_bytes);
    let riff_size = data_bytes.saturating_add(HEADER_LEN as u64 - 8);
    let frames = data_bytes / u64::from(channels.block_align());

    let mut bytes = Vec::with_capacity(HEADER_LEN);
    match form {
        Form::Riff => {
            bytes.extend_from_slice(b"RIFF");
            bytes.extend_from_slice(&narrow(riff_size).to_le_bytes());
            bytes.extend_from_slice(b"WAVE");
            bytes.extend_from_slice(b"JUNK");
            bytes.extend_from_slice(&DS64_LEN.to_le_bytes());
            bytes.extend_from_slice(&[0; DS64_LEN as usize]);
        }
        Form::Rf64 => {
            bytes.extend_from_slice(b"RF64");
            bytes.extend_from_slice(&SEE_DS64.to_le_bytes());
            bytes.extend_from_slice(b"WAVE");
            bytes.extend_from_slice(b"ds64");
            bytes.extend_from_slice(&DS64_LEN.to_le_bytes());
            bytes.extend_from_slice(&riff_size.to_le_bytes());
            bytes.extend_from_slice(&data_bytes.to_le_bytes());
            bytes.extend_from_slice(&frames.to_le_bytes());
            // no table of other chunks' sizes
            bytes.extend_from_slice(&0_u32.to_le_bytes());
        }
    }
    bytes.extend_from_slice(b"fmt ");
    bytes.extend_from_slice(&16_u32.to_le_bytes());
    bytes.extend_from_slice(&FORMAT_PCM.to_le_bytes());
    bytes.extend_from_slice(&channels.count().to_le_bytes());
    bytes.extend_from_slice(&rate.to_le_bytes());
    bytes.extend_from_slice(&byte_rate.to_le_bytes());
    bytes.extend_from_slice(&channels.block_align().to_le_bytes());
    bytes.extend_from_slice(&BITS_PER_SAMPLE.to_le_bytes());
    bytes.extend_from_slice(b"data");
    let data_size = match form {
        Form::Riff => narrow(data_bytes),
        Form::Rf64 => SEE_DS64,
    };
    bytes.extend_from_slice(&data_size.to_le_bytes());

    let mut header = [0; HEADER_LEN];
    for (slot, byte) in header.iter_mut().zip(bytes) {
        *slot = byte;
    }
    Ok(header)
}

fn byte_rate(rate: u32, channels: Channels) -> Result<u32, Error> {
    if rate == 0 {
        return Err(Error::Rate(rate));
    }
    rate.checked_mul(u32::from(channels.block_align()))
        .ok_or(Error::Rate(rate))
}

/// A size [`Form::for_data`] has already found to fit in 32 bits.
fn narrow(size: u64) -> u32 {
    u32::try_from(size).unwrap_or(SEE_DS64)
}

/// Writes a WAV file to any [`Write`] that can also [`Seek`], as it goes.
///
/// The header is written with zero sizes when the writer is built, samples
/// are appended as they come, and [`finish`](Self::finish) goes back and
/// writes the real sizes, as RIFF or as RF64. A file whose writer was
/// dropped without finishing has its samples but says it has none.
#[derive(Debug)]
pub struct Writer<W: Write + Seek> {
    out: W,
    start: u64,
    rate: u32,
    channels: Channels,
    data_bytes: u64,
    scratch: Vec<u8>,
}

/// Samples converted per write to the sink.
const CHUNK_SAMPLES: usize = 2_048;

impl<W: Write + Seek> Writer<W> {
    /// Start a file at the sink's current position.
    ///
    /// # Errors
    ///
    /// [`Error::Rate`] for a rate no header can carry, and [`Error::Io`]
    /// when the header could not be written.
    pub fn new(mut out: W, rate: u32, channels: Channels) -> Result<Self, Error> {
        let placeholder = header(rate, channels, 0)?;
        let start = out.stream_position()?;
        out.write_all(&placeholder)?;
        Ok(Self {
            out,
            start,
            rate,
            channels,
            data_bytes: 0,
            scratch: Vec::with_capacity(CHUNK_SAMPLES * 2),
        })
    }

    /// The sampling rate.
    #[must_use]
    pub const fn rate(&self) -> u32 {
        self.rate
    }

    /// The channels.
    #[must_use]
    pub const fn channels(&self) -> Channels {
        self.channels
    }

    /// The octets of samples written so far.
    #[must_use]
    pub const fn data_bytes(&self) -> u64 {
        self.data_bytes
    }

    /// The form the file would be finished in now.
    #[must_use]
    pub const fn form(&self) -> Form {
        Form::for_data(self.data_bytes)
    }

    /// Append frames already interleaved: for stereo, local then remote,
    /// one pair per frame.
    ///
    /// # Errors
    ///
    /// [`Error::PartialFrame`] when the samples do not divide into frames,
    /// and [`Error::Io`] when the sink failed.
    pub fn write_interleaved(&mut self, samples: &[i16]) -> Result<(), Error> {
        let channels = usize::from(self.channels.count());
        if !samples.len().is_multiple_of(channels) {
            return Err(Error::PartialFrame {
                samples: samples.len(),
            });
        }
        for chunk in samples.chunks(CHUNK_SAMPLES) {
            self.scratch.clear();
            for sample in chunk {
                self.scratch.extend_from_slice(&sample.to_le_bytes());
            }
            self.append()?;
        }
        Ok(())
    }

    /// Append one frame for each pair of samples: `local` on the left,
    /// `remote` on the right.
    ///
    /// # Errors
    ///
    /// [`Error::NotStereo`] on a mono file, [`Error::Lengths`] when the two
    /// sides differ in length, and [`Error::Io`] when the sink failed.
    pub fn write_stereo(&mut self, local: &[i16], remote: &[i16]) -> Result<(), Error> {
        if self.channels != Channels::Stereo {
            return Err(Error::NotStereo);
        }
        if local.len() != remote.len() {
            return Err(Error::Lengths {
                local: local.len(),
                remote: remote.len(),
            });
        }
        let frames = CHUNK_SAMPLES / 2;
        for (left, right) in local.chunks(frames).zip(remote.chunks(frames)) {
            self.scratch.clear();
            for (l, r) in left.iter().zip(right) {
                self.scratch.extend_from_slice(&l.to_le_bytes());
                self.scratch.extend_from_slice(&r.to_le_bytes());
            }
            self.append()?;
        }
        Ok(())
    }

    fn append(&mut self) -> Result<(), Error> {
        self.out.write_all(&self.scratch)?;
        let written = u64::try_from(self.scratch.len()).unwrap_or(u64::MAX);
        // sixteen exbibytes of audio: the counter saturates rather than wraps
        self.data_bytes = self.data_bytes.saturating_add(written);
        Ok(())
    }

    /// Write the sizes the file has reached into the header without ending
    /// it, and flush the sink.
    ///
    /// What makes a long recording survive the process that writes it: a
    /// file checkpointed every few seconds and then abandoned — a crash, a
    /// power cut — opens in any player with everything up to the last
    /// checkpoint, where one that was only ever finished at the end says it
    /// holds nothing. Samples written after it are still in the file, past
    /// the length the header states.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the sink could not seek, be written or flush.
    pub fn checkpoint(&mut self) -> Result<(), Error> {
        self.write_header()?;
        self.out.flush()?;
        Ok(())
    }

    /// Write the real sizes into the header, leave the sink positioned after
    /// the last sample, flush it and hand it back.
    ///
    /// Sixteen-bit samples always leave the data chunk an even length, so
    /// no pad octet is ever needed.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the sink could not seek, be written or flush.
    pub fn finish(mut self) -> Result<W, Error> {
        self.write_header()?;
        self.out.flush()?;
        Ok(self.out)
    }

    /// The header for the sizes so far, written over the one at the start,
    /// with the sink left where the next sample goes.
    fn write_header(&mut self) -> Result<(), Error> {
        let header = header(self.rate, self.channels, self.data_bytes)?;
        let end = self.out.stream_position()?;
        self.out.seek(SeekFrom::Start(self.start))?;
        self.out.write_all(&header)?;
        self.out.seek(SeekFrom::Start(end))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Channels, Error, Form, HEADER_LEN, MAX_RIFF_DATA, Writer, header};
    use std::io::{Cursor, Seek, SeekFrom, Write};

    fn u16_at(bytes: &[u8], at: usize) -> u16 {
        u16::from_le_bytes(bytes[at..at + 2].try_into().unwrap())
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn a_mono_header_is_riff_wave_pcm_with_a_junk_chunk_reserved() {
        let bytes = header(8_000, Channels::Mono, 320).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(b"RIFF");
        expected.extend_from_slice(&(320_u32 + 72).to_le_bytes());
        expected.extend_from_slice(b"WAVE");
        expected.extend_from_slice(b"JUNK");
        expected.extend_from_slice(&28_u32.to_le_bytes());
        expected.extend_from_slice(&[0; 28]);
        expected.extend_from_slice(b"fmt ");
        expected.extend_from_slice(&16_u32.to_le_bytes());
        expected.extend_from_slice(&1_u16.to_le_bytes()); // PCM
        expected.extend_from_slice(&1_u16.to_le_bytes()); // one channel
        expected.extend_from_slice(&8_000_u32.to_le_bytes());
        expected.extend_from_slice(&16_000_u32.to_le_bytes()); // byte rate
        expected.extend_from_slice(&2_u16.to_le_bytes()); // block align
        expected.extend_from_slice(&16_u16.to_le_bytes()); // bits
        expected.extend_from_slice(b"data");
        expected.extend_from_slice(&320_u32.to_le_bytes());
        assert_eq!(expected.len(), HEADER_LEN);
        assert_eq!(&bytes[..], &expected[..]);
    }

    #[test]
    fn a_stereo_header_doubles_the_frame() {
        for rate in [8_000_u32, 16_000, 44_100, 48_000, 11_025] {
            let bytes = header(rate, Channels::Stereo, 4_000).unwrap();
            assert_eq!(u16_at(&bytes, 56), 1, "PCM");
            assert_eq!(u16_at(&bytes, 58), 2, "channels");
            assert_eq!(u32_at(&bytes, 60), rate);
            assert_eq!(u32_at(&bytes, 64), rate * 4, "byte rate");
            assert_eq!(u16_at(&bytes, 68), 4, "block align");
            assert_eq!(u16_at(&bytes, 70), 16, "bits per sample");
            assert_eq!(u32_at(&bytes, 76), 4_000);
            assert_eq!(u32_at(&bytes, 4), 4_072);
        }
    }

    #[test]
    fn the_form_changes_where_the_riff_size_stops_fitting() {
        // the RIFF size is the data plus 72, and must stay below all ones
        assert_eq!(MAX_RIFF_DATA, 0xFFFF_FFFF - 1 - 72);
        assert_eq!(Form::for_data(0), Form::Riff);
        assert_eq!(Form::for_data(MAX_RIFF_DATA), Form::Riff);
        assert_eq!(Form::for_data(MAX_RIFF_DATA + 1), Form::Rf64);
        assert_eq!(Form::for_data(u64::MAX), Form::Rf64);

        let last = header(48_000, Channels::Stereo, MAX_RIFF_DATA).unwrap();
        assert_eq!(&last[0..4], b"RIFF");
        assert_eq!(u32_at(&last, 4), 0xFFFF_FFFE);
        assert_eq!(&last[12..16], b"JUNK");
        assert_eq!(u32_at(&last, 76), 0xFFFF_FFFE - 72);

        let first = header(48_000, Channels::Stereo, MAX_RIFF_DATA + 1).unwrap();
        assert_eq!(&first[0..4], b"RF64");
        assert_eq!(u32_at(&first, 4), 0xFFFF_FFFF);
        assert_eq!(&first[12..16], b"ds64");
        assert_eq!(u32_at(&first, 16), 28);
        assert_eq!(u64_at(&first, 20), 0xFFFF_FFFF, "64-bit RIFF size");
        assert_eq!(u64_at(&first, 28), MAX_RIFF_DATA + 1, "64-bit data size");
        assert_eq!(u32_at(&first, 44), 0, "no table");
        assert_eq!(&first[48..52], b"fmt ");
        assert_eq!(&first[72..76], b"data");
        assert_eq!(u32_at(&first, 76), 0xFFFF_FFFF);
    }

    #[test]
    fn an_rf64_header_counts_frames_and_carries_sizes_past_32_bits() {
        let data = 6 * 1024 * 1024 * 1024_u64;
        let bytes = header(48_000, Channels::Stereo, data).unwrap();
        assert_eq!(u64_at(&bytes, 20), data + 72);
        assert_eq!(u64_at(&bytes, 28), data);
        assert_eq!(u64_at(&bytes, 36), data / 4, "frames of the stereo file");
        let bytes = header(8_000, Channels::Mono, data).unwrap();
        assert_eq!(u64_at(&bytes, 36), data / 2, "frames of the mono file");
    }

    #[test]
    fn a_rate_no_header_can_carry_is_refused() {
        assert!(matches!(header(0, Channels::Mono, 0), Err(Error::Rate(0))));
        // four octets a frame: the byte rate overflows past a quarter of 2^32
        let too_fast = u32::MAX / 4 + 1;
        assert!(matches!(
            header(too_fast, Channels::Stereo, 0),
            Err(Error::Rate(rate)) if rate == too_fast
        ));
        assert!(header(too_fast, Channels::Mono, 0).is_ok());
        assert!(header(u32::MAX / 4, Channels::Stereo, 0).is_ok());
        assert!(matches!(
            Writer::new(Cursor::new(Vec::new()), 0, Channels::Stereo),
            Err(Error::Rate(0))
        ));
    }

    #[test]
    fn a_stereo_file_puts_the_local_side_left_and_the_remote_side_right() {
        let mut writer = Writer::new(Cursor::new(Vec::new()), 16_000, Channels::Stereo).unwrap();
        let local: Vec<i16> = (0..3_000).map(|n| n * 3).collect();
        let remote: Vec<i16> = (0..3_000).map(|n| -n - 1).collect();
        writer.write_stereo(&local, &remote).unwrap();
        writer.write_interleaved(&[0x1234, -2]).unwrap();
        assert_eq!(writer.data_bytes(), 3_001 * 4);
        assert_eq!(writer.form(), Form::Riff);
        let bytes = writer.finish().unwrap().into_inner();

        assert_eq!(bytes.len(), HEADER_LEN + 3_001 * 4);
        assert_eq!(
            &bytes[..HEADER_LEN],
            &header(16_000, Channels::Stereo, 12_004).unwrap()
        );
        let samples: Vec<i16> = bytes[HEADER_LEN..]
            .chunks(2)
            .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        for (frame, pair) in samples.chunks(2).take(3_000).enumerate() {
            assert_eq!(pair, [local[frame], remote[frame]]);
        }
        assert_eq!(&samples[6_000..], &[0x1234, -2]);
        // little-endian on disk
        assert_eq!(
            &bytes[HEADER_LEN + 12_000..HEADER_LEN + 12_002],
            &[0x34, 0x12]
        );
    }

    #[test]
    fn the_header_is_patched_where_the_file_started_and_the_sink_left_at_the_end() {
        let mut sink = Cursor::new(Vec::new());
        sink.write_all(b"prefix").unwrap();
        let mut writer = Writer::new(sink, 8_000, Channels::Mono).unwrap();
        writer.write_interleaved(&[1, 2, 3]).unwrap();
        let mut sink = writer.finish().unwrap();
        assert_eq!(sink.stream_position().unwrap(), 6 + 80 + 6);
        sink.write_all(b"!").unwrap();
        let bytes = sink.into_inner();
        assert_eq!(&bytes[..6], b"prefix");
        assert_eq!(&bytes[6..86], &header(8_000, Channels::Mono, 6).unwrap());
        assert_eq!(bytes.last(), Some(&b'!'));
    }

    /// A checkpoint is a finish that keeps writing: the header states what
    /// has been written so far, and the next samples land after the last
    /// ones rather than over the header.
    #[test]
    fn a_checkpoint_states_the_sizes_so_far_and_writing_carries_on_after_it() {
        let mut writer = Writer::new(Cursor::new(Vec::new()), 8_000, Channels::Stereo).unwrap();
        writer.write_stereo(&[1, 2], &[3, 4]).unwrap();
        writer.checkpoint().unwrap();
        assert_eq!(
            &writer.out.get_ref()[..HEADER_LEN],
            &header(8_000, Channels::Stereo, 8).unwrap(),
            "an abandoned file would open with the two frames in it"
        );
        writer.write_stereo(&[5], &[6]).unwrap();
        assert_eq!(
            u32_at(writer.out.get_ref(), 76),
            8,
            "the frame after the checkpoint is not stated until the next one"
        );
        let bytes = writer.finish().unwrap().into_inner();
        assert_eq!(bytes.len(), HEADER_LEN + 12);
        assert_eq!(
            &bytes[..HEADER_LEN],
            &header(8_000, Channels::Stereo, 12).unwrap()
        );
        assert_eq!(&bytes[HEADER_LEN + 8..], &[5, 0, 6, 0]);
    }

    #[test]
    fn a_file_that_grew_past_the_limit_is_finished_as_rf64() {
        // four gibibytes are not written here: the count of what was written
        // is set to just below the limit, and the last few frames go over it
        let mut writer = Writer::new(Cursor::new(Vec::new()), 48_000, Channels::Stereo).unwrap();
        writer.data_bytes = MAX_RIFF_DATA - 2;
        writer.write_stereo(&[1], &[2]).unwrap();
        assert_eq!(writer.form(), Form::Rf64);
        let mut sink = writer.finish().unwrap();
        sink.seek(SeekFrom::Start(0)).unwrap();
        let bytes = sink.into_inner();
        assert_eq!(&bytes[..4], b"RF64");
        assert_eq!(&bytes[12..16], b"ds64");
        assert_eq!(u64_at(&bytes, 28), MAX_RIFF_DATA + 2);

        let mut writer = Writer::new(Cursor::new(Vec::new()), 48_000, Channels::Stereo).unwrap();
        writer.data_bytes = MAX_RIFF_DATA - 6;
        writer.write_stereo(&[1], &[2]).unwrap();
        assert_eq!(writer.form(), Form::Riff);
        let bytes = writer.finish().unwrap().into_inner();
        assert_eq!(&bytes[..4], b"RIFF");
        assert_eq!(u32_at(&bytes, 4), 0xFFFF_FFFE - 2);
    }

    #[test]
    fn frames_that_do_not_add_up_are_refused() {
        let mut stereo = Writer::new(Cursor::new(Vec::new()), 8_000, Channels::Stereo).unwrap();
        assert!(matches!(
            stereo.write_interleaved(&[1, 2, 3]),
            Err(Error::PartialFrame { samples: 3 })
        ));
        assert!(matches!(
            stereo.write_stereo(&[1, 2], &[3]),
            Err(Error::Lengths {
                local: 2,
                remote: 1
            })
        ));
        assert_eq!(stereo.data_bytes(), 0, "nothing of either was written");

        let mut mono = Writer::new(Cursor::new(Vec::new()), 8_000, Channels::Mono).unwrap();
        assert!(matches!(
            mono.write_stereo(&[1], &[2]),
            Err(Error::NotStereo)
        ));
        mono.write_interleaved(&[1, 2, 3]).unwrap();
        assert_eq!(mono.data_bytes(), 6);
        assert_eq!(mono.channels(), Channels::Mono);
        assert_eq!(mono.rate(), 8_000);
    }
}
