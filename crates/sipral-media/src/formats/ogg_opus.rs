// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Opus in Ogg, RFC 7845: the `.opus` file.
//!
//! An Ogg Opus stream is two header packets and then audio (§3). The
//! identification header, [`OpusHead`], sits alone on the first page, marked
//! BOS; the comment header, [`OpusTags`], ends the second; every page after
//! that carries Opus packets, one packet per Ogg packet, and the last is
//! marked EOS. Both header pages have granule position zero.
//!
//! # Granule positions
//!
//! Whatever rate the audio was encoded at, the granule position counts
//! samples at 48 kHz (§4): on each page, the number of samples decoded from
//! the start of the stream up to the end of the last packet that finishes on
//! that page. The first [pre-skip](OpusHead::pre_skip) of those samples is
//! the encoder's lookahead, which a player decodes and throws away (§4.2),
//! so the playable length of a stream is its final granule position less the
//! pre-skip. An encoder pads the end of the audio out to a whole frame;
//! setting the last page's granule position below what its packets add up
//! to tells a player to drop the padding (§4.4), and that is what
//! [`Writer::finish`] does when it is told the real length.
//!
//! # Latency
//!
//! [`Writer`] holds the most recent packet back until the next one arrives,
//! because only then does it know that packet is not the last one and does
//! not need the end trimming. Every other packet goes onto a page, and a
//! page is written out as soon as the audio on it reaches the configured
//! duration, one second unless [`Writer::set_max_page_duration`] says
//! otherwise. A packet therefore reaches the sink at most that duration plus
//! one packet after it was handed over, which bounds both what a crash can
//! lose and what a reader following the file live has to wait for.
//!
//! The packets come from elsewhere, already encoded, with their durations;
//! in this crate that is `opus::Encoder`, whose `FrameDuration` gives the
//! 48 kHz duration of a packet as `timestamp_increment`. Nothing here needs
//! the `opus` feature.

use super::ogg::{self, PageWriter};
use core::fmt;
use std::io::{self, Write};

/// The rate granule positions count at, whatever the input rate (§4).
pub const GRANULE_RATE: u32 = 48_000;

/// The magic signature that opens the identification header (§5.1).
pub const HEAD_MAGIC: [u8; 8] = *b"OpusHead";

/// The magic signature that opens the comment header (§5.2).
pub const TAGS_MAGIC: [u8; 8] = *b"OpusTags";

/// The identification header version this writes (§5.1).
pub const HEAD_VERSION: u8 = 1;

/// The length of an identification header with channel mapping family 0,
/// which carries no channel mapping table (§5.1.1).
pub const HEAD_LEN: usize = 19;

/// The vendor string this writes into the comment header.
pub const VENDOR: &str = "sipral";

/// The shortest duration an Opus packet can have, and the unit every
/// packet duration is a multiple of: 2.5 ms at [`GRANULE_RATE`] (RFC 6716
/// §2.1.4).
pub const MIN_PACKET_SAMPLES: u32 = 120;

/// The longest duration an Opus packet can have: 120 ms at
/// [`GRANULE_RATE`] (RFC 6716 §3.2.5).
pub const MAX_PACKET_SAMPLES: u32 = 5_760;

/// How much audio a page holds before it is written out, when nothing says
/// otherwise, in milliseconds.
pub const DEFAULT_MAX_PAGE_MS: u32 = 1_000;

/// How many channels the stream carries.
///
/// Channel mapping family 0 (§5.1.1.1) covers these two and no others: mono,
/// or stereo with the left channel first. Family 0 is what is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channels {
    /// One channel.
    Mono,
    /// Two channels, left then right.
    Stereo,
}

impl Channels {
    /// The channel count the header carries.
    #[must_use]
    pub const fn count(self) -> u8 {
        match self {
            Self::Mono => 1,
            Self::Stereo => 2,
        }
    }
}

/// The identification header (§5.1).
///
/// Written with version 1, an output gain of zero and channel mapping
/// family 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpusHead {
    channels: Channels,
    pre_skip: u16,
    input_sample_rate: u32,
}

impl OpusHead {
    /// A header for `channels`, whose first `pre_skip` samples at 48 kHz are
    /// the encoder's lookahead, encoded from audio at `input_sample_rate`.
    ///
    /// The pre-skip is what the encoder reports as its lookahead, converted
    /// to 48 kHz (§4.2); a player discards that many samples from the start.
    /// The input sample rate is informational and changes nothing about
    /// decoding (§5.1); zero means it is not known.
    #[must_use]
    pub const fn new(channels: Channels, pre_skip: u16, input_sample_rate: u32) -> Self {
        Self {
            channels,
            pre_skip,
            input_sample_rate,
        }
    }

    /// The channels.
    #[must_use]
    pub const fn channels(&self) -> Channels {
        self.channels
    }

    /// The samples at 48 kHz a player discards from the start.
    #[must_use]
    pub const fn pre_skip(&self) -> u16 {
        self.pre_skip
    }

    /// The rate the audio was encoded from, zero when unknown.
    #[must_use]
    pub const fn input_sample_rate(&self) -> u32 {
        self.input_sample_rate
    }

    /// The header as it goes into the stream: the magic signature, the
    /// version, the channel count, the pre-skip, the input sample rate, the
    /// output gain and the mapping family, multi-octet fields little-endian.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; HEAD_LEN] {
        let mut bytes = [0; HEAD_LEN];
        let fields = HEAD_MAGIC
            .iter()
            .copied()
            .chain([HEAD_VERSION, self.channels.count()])
            .chain(self.pre_skip.to_le_bytes())
            .chain(self.input_sample_rate.to_le_bytes())
            // output gain, Q7.8 dB
            .chain(0_i16.to_le_bytes())
            // channel mapping family
            .chain([0]);
        for (slot, value) in bytes.iter_mut().zip(fields) {
            *slot = value;
        }
        bytes
    }
}

/// A comment field name that the comment header cannot carry.
///
/// §5.2 takes its user comments from the Vorbis comment format: `NAME=value`,
/// where the name is one or more ASCII characters from 0x20 to 0x7D, and not
/// `=`, which ends it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldNameError {
    /// The name that was refused.
    pub name: String,
}

impl fmt::Display for FieldNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} is not a comment field name", self.name)
    }
}

impl core::error::Error for FieldNameError {}

/// The comment header (§5.2): the vendor string [`VENDOR`] and the user
/// comments given, none unless some are added.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OpusTags {
    comments: Vec<String>,
}

impl OpusTags {
    /// A comment header with no user comments.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            comments: Vec::new(),
        }
    }

    /// Add the user comment `name=value`.
    ///
    /// # Errors
    ///
    /// [`FieldNameError`] when the name is empty or has a character outside
    /// 0x20 to 0x7D, or an `=`.
    pub fn add(&mut self, name: &str, value: &str) -> Result<(), FieldNameError> {
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|byte| (0x20..=0x7D).contains(&byte) && byte != b'=');
        if !valid {
            return Err(FieldNameError {
                name: name.to_owned(),
            });
        }
        self.comments.push(format!("{name}={value}"));
        Ok(())
    }

    /// The user comments, each as `NAME=value`.
    #[must_use]
    pub fn comments(&self) -> &[String] {
        &self.comments
    }

    /// The header as it goes into the stream: the magic signature, the
    /// vendor string's length and octets, the comment count, and each
    /// comment's length and octets, lengths as 32-bit little-endian.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&TAGS_MAGIC);
        push_string(&mut bytes, VENDOR);
        bytes.extend_from_slice(&length_field(self.comments.len()));
        for comment in &self.comments {
            push_string(&mut bytes, comment);
        }
        bytes
    }
}

fn push_string(bytes: &mut Vec<u8>, string: &str) {
    bytes.extend_from_slice(&length_field(string.len()));
    bytes.extend_from_slice(string.as_bytes());
}

/// A length as the comment header stores it. Nothing that fits in memory
/// here comes near four gibibytes; a longer one saturates rather than wraps.
fn length_field(length: usize) -> [u8; 4] {
    u32::try_from(length).unwrap_or(u32::MAX).to_le_bytes()
}

/// Why the [`Writer`] refused.
#[derive(Debug)]
pub enum Error {
    /// The sink failed.
    Io(io::Error),
    /// An empty packet: an Opus packet has at least its TOC octet (RFC 6716
    /// §3.1).
    EmptyPacket,
    /// A packet duration that no Opus packet has: not a multiple of
    /// [`MIN_PACKET_SAMPLES`] or above [`MAX_PACKET_SAMPLES`].
    Duration {
        /// What was given, in samples at 48 kHz.
        samples: u32,
    },
    /// A page duration of zero.
    PageDuration,
    /// A length that the last page cannot express: longer than the audio
    /// written, or short enough to reach back before the start of the last
    /// page (§4.4).
    Length {
        /// The length asked for, in samples at 48 kHz after the pre-skip.
        requested: u64,
        /// The shortest length that can be expressed.
        min: u64,
        /// The longest.
        max: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "writing the Ogg Opus stream failed: {error}"),
            Self::EmptyPacket => f.write_str("an empty Opus packet"),
            Self::Duration { samples } => {
                write!(f, "no Opus packet lasts {samples} samples at 48 kHz")
            }
            Self::PageDuration => f.write_str("a page duration of zero"),
            Self::Length {
                requested,
                min,
                max,
            } => write!(
                f,
                "a length of {requested} samples, where the last page can say {min} to {max}"
            ),
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

impl From<ogg::WriteError> for Error {
    fn from(error: ogg::WriteError) -> Self {
        match error {
            ogg::WriteError::Io(error) => Self::Io(error),
            // the writer is consumed by finish, so its page writer never
            // sees a second end
            ogg::WriteError::Finished => {
                Self::Io(io::Error::other("the Ogg stream has already ended"))
            }
        }
    }
}

/// Writes an Ogg Opus stream to any [`Write`], as it goes.
///
/// The headers are written when it is built; each packet after that is
/// written as its page fills (see the module documentation for the latency),
/// and [`finish`](Self::finish) writes the last page and hands the sink
/// back. Dropping the writer without finishing leaves a stream with no EOS
/// page, which players generally read up to its last whole page.
#[derive(Debug)]
pub struct Writer<W: Write> {
    out: W,
    pages: PageWriter,
    pre_skip: u64,
    /// The granule position at the end of the last packet put on a page.
    granule: u64,
    /// The granule position of the last page written, a lower bound for
    /// the final one.
    written_granule: u64,
    /// Samples on the page being filled.
    page_samples: u64,
    max_page_samples: u64,
    held: Vec<u8>,
    held_samples: u32,
}

impl<W: Write> Writer<W> {
    /// Start a stream with this serial number on `out`, writing its two
    /// header pages.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the headers could not be written.
    pub fn new(mut out: W, head: &OpusHead, tags: &OpusTags, serial: u32) -> Result<Self, Error> {
        let mut pages = PageWriter::new(serial);
        pages.write_packet(&mut out, &head.to_bytes(), 0)?;
        pages.flush(&mut out)?;
        pages.write_packet(&mut out, &tags.to_bytes(), 0)?;
        pages.flush(&mut out)?;
        Ok(Self {
            out,
            pages,
            pre_skip: u64::from(head.pre_skip()),
            granule: 0,
            written_granule: 0,
            page_samples: 0,
            max_page_samples: u64::from(DEFAULT_MAX_PAGE_MS) * u64::from(GRANULE_RATE / 1_000),
            held: Vec::new(),
            held_samples: 0,
        })
    }

    /// Write a page out once the audio on it reaches `millis` milliseconds.
    ///
    /// # Errors
    ///
    /// [`Error::PageDuration`] for zero.
    pub fn set_max_page_duration(&mut self, millis: u32) -> Result<(), Error> {
        if millis == 0 {
            return Err(Error::PageDuration);
        }
        self.max_page_samples = u64::from(millis) * u64::from(GRANULE_RATE / 1_000);
        Ok(())
    }

    /// The sink, for a look at what has been written so far.
    pub const fn get_ref(&self) -> &W {
        &self.out
    }

    /// The granule position the stream has reached: every sample at 48 kHz
    /// handed over so far, the pre-skip included.
    #[must_use]
    pub fn granule_position(&self) -> u64 {
        self.granule + u64::from(self.held_samples)
    }

    /// Add one encoded packet that decodes to `samples` samples at 48 kHz.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyPacket`] and [`Error::Duration`] for a packet no Opus
    /// encoder produces, and [`Error::Io`] when a page could not be written.
    pub fn write_packet(&mut self, packet: &[u8], samples: u32) -> Result<(), Error> {
        if packet.is_empty() {
            return Err(Error::EmptyPacket);
        }
        if samples == 0
            || !samples.is_multiple_of(MIN_PACKET_SAMPLES)
            || samples > MAX_PACKET_SAMPLES
        {
            return Err(Error::Duration { samples });
        }
        if self.held_samples > 0 {
            let end = self.granule + u64::from(self.held_samples);
            self.commit(end)?;
        }
        self.held.clear();
        self.held.extend_from_slice(packet);
        self.held_samples = samples;
        Ok(())
    }

    /// Write out the page being filled, and flush the sink.
    ///
    /// The packet held back for the end trimming stays held.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the page could not be written or the sink not
    /// flushed.
    pub fn flush(&mut self) -> Result<(), Error> {
        if !self.pages.is_empty() {
            self.pages.flush(&mut self.out)?;
            self.written_granule = self.granule;
            self.page_samples = 0;
        }
        self.out.flush()?;
        Ok(())
    }

    /// End the stream and hand the sink back.
    ///
    /// `length` is how much audio there really is, in samples at 48 kHz
    /// after the pre-skip; the last page's granule position becomes the
    /// pre-skip plus that, so a player drops whatever the last packet was
    /// padded with (§4.4). `None` keeps every sample the packets decode to.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] when the last page cannot express that length: it
    /// is longer than the audio, or so short that it would trim samples off
    /// an earlier page. [`Error::Io`] when the last page could not be written
    /// or the sink not flushed.
    pub fn finish(mut self, length: Option<u64>) -> Result<W, Error> {
        if self.held_samples == 0 {
            if let Some(requested) = length.filter(|requested| *requested > 0) {
                return Err(Error::Length {
                    requested,
                    min: 0,
                    max: 0,
                });
            }
            self.pages.finish(&mut self.out)?;
        } else {
            let max = self.granule + u64::from(self.held_samples);
            // a last packet that does not fit the segment table sends out
            // the page being filled first, and that page ends where the
            // packets on it do
            let floor = if !self.pages.is_empty() && !self.pages.fits(self.held.len()) {
                self.granule
            } else {
                self.written_granule
            };
            let end = match length {
                None => max,
                Some(requested) => {
                    let end = self.pre_skip.saturating_add(requested);
                    if end > max || end < floor {
                        return Err(Error::Length {
                            requested,
                            min: floor.saturating_sub(self.pre_skip),
                            max: max.saturating_sub(self.pre_skip),
                        });
                    }
                    end
                }
            };
            let packet = core::mem::take(&mut self.held);
            self.pages.write_packet(&mut self.out, &packet, end)?;
            self.pages.finish(&mut self.out)?;
        }
        self.out.flush()?;
        Ok(self.out)
    }

    /// Put the held packet on a page, ending at `end`, and write the page
    /// out if it is now long enough.
    fn commit(&mut self, end: u64) -> Result<(), Error> {
        let before = self.pages.pages_written();
        self.pages.write_packet(&mut self.out, &self.held, end)?;
        if self.pages.pages_written() != before {
            // the segment table filled on the way: whatever pages went out
            // held packets ending no later than the previous one
            self.written_granule = self.granule;
            self.page_samples = 0;
        }
        self.granule = end;
        self.page_samples += u64::from(self.held_samples);
        if self.page_samples >= self.max_page_samples {
            self.pages.flush(&mut self.out)?;
            self.written_granule = self.granule;
            self.page_samples = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Channels, DEFAULT_MAX_PAGE_MS, Error, HEAD_LEN, OpusHead, OpusTags, VENDOR, Writer,
    };
    use crate::formats::ogg::{FLAG_BOS, FLAG_EOS, Page, read_packets};

    fn pages(bytes: &[u8]) -> Vec<Page<'_>> {
        let mut rest = bytes;
        let mut out = Vec::new();
        while !rest.is_empty() {
            let (page, used) = Page::parse(rest).unwrap();
            out.push(page);
            rest = &rest[used..];
        }
        out
    }

    /// A packet whose octets say which one it is, so a round trip can check
    /// order as well as content.
    fn packet(index: usize) -> Vec<u8> {
        let tag = index.to_le_bytes();
        (0..40 + index % 7)
            .map(|n| tag[n % 2] ^ n.to_le_bytes()[0])
            .collect()
    }

    fn head() -> OpusHead {
        OpusHead::new(Channels::Mono, 312, 16_000)
    }

    #[test]
    fn the_identification_header_is_laid_out_as_section_5_1_says() {
        let bytes = OpusHead::new(Channels::Mono, 312, 48_000).to_bytes();
        assert_eq!(HEAD_LEN, 19);
        assert_eq!(
            bytes,
            [
                b'O', b'p', b'u', b's', b'H', b'e', b'a', b'd', // magic
                1,    // version
                1,    // channels
                0x38, 0x01, // pre-skip 312, little-endian
                0x80, 0xBB, 0x00, 0x00, // 48000
                0x00, 0x00, // output gain
                0,    // mapping family
            ]
        );
        let stereo = OpusHead::new(Channels::Stereo, 0x0F00, 8_000).to_bytes();
        assert_eq!(stereo[9], 2);
        assert_eq!(&stereo[10..12], &[0x00, 0x0F]);
        assert_eq!(&stereo[12..16], &8_000_u32.to_le_bytes());
        assert_eq!(&stereo[16..], &[0, 0, 0]);
    }

    #[test]
    fn the_comment_header_carries_the_vendor_and_nothing_else_unless_asked() {
        let bytes = OpusTags::new().to_bytes();
        let mut expected = b"OpusTags".to_vec();
        expected.extend_from_slice(&6_u32.to_le_bytes());
        expected.extend_from_slice(b"sipral");
        expected.extend_from_slice(&0_u32.to_le_bytes());
        assert_eq!(VENDOR, "sipral");
        assert_eq!(bytes, expected);

        let mut tags = OpusTags::new();
        tags.add("TITLE", "call 17").unwrap();
        tags.add("ENCODER", "").unwrap();
        let bytes = tags.to_bytes();
        let mut expected = b"OpusTags".to_vec();
        expected.extend_from_slice(&6_u32.to_le_bytes());
        expected.extend_from_slice(b"sipral");
        expected.extend_from_slice(&2_u32.to_le_bytes());
        expected.extend_from_slice(&13_u32.to_le_bytes());
        expected.extend_from_slice(b"TITLE=call 17");
        expected.extend_from_slice(&8_u32.to_le_bytes());
        expected.extend_from_slice(b"ENCODER=");
        assert_eq!(bytes, expected);
        assert_eq!(tags.comments(), ["TITLE=call 17", "ENCODER="]);
    }

    #[test]
    fn a_field_name_outside_the_vorbis_comment_alphabet_is_refused() {
        let mut tags = OpusTags::new();
        for name in ["", "A=B", "TILDE~", "CAF\u{e9}", "TAB\t"] {
            let error = tags.add(name, "x").unwrap_err();
            assert_eq!(error.name, name);
        }
        // both ends of 0x20..=0x7D are in
        tags.add(" }", "edge").unwrap();
        assert_eq!(tags.comments(), [" }=edge"]);
    }

    #[test]
    fn the_headers_take_a_page_each_and_the_audio_starts_on_the_third() {
        let writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 0xCAFE).unwrap();
        let written = writer.get_ref().clone();
        let bytes = writer.finish(None).unwrap();
        assert_eq!(&bytes[..written.len()], &written[..]);

        let pages = pages(&bytes);
        assert_eq!(pages.len(), 3);
        assert_eq!(pages[0].flags(), FLAG_BOS);
        assert_eq!(pages[0].granule(), 0);
        assert_eq!(pages[0].body(), &head().to_bytes());
        assert_eq!(pages[0].lacing(), &[19]);
        assert_eq!(pages[1].flags(), 0);
        assert_eq!(pages[1].granule(), 0);
        assert_eq!(pages[1].body(), &OpusTags::new().to_bytes()[..]);
        assert_eq!(pages[2].flags(), FLAG_EOS);
        assert!(pages.iter().all(|page| page.serial() == 0xCAFE));
    }

    #[test]
    fn a_stream_round_trips_with_granules_counted_at_48_khz_and_the_end_trimmed() {
        let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        for index in 0..100 {
            writer.write_packet(&packet(index), 960).unwrap();
        }
        assert_eq!(writer.granule_position(), 96_000);
        // two seconds of 20 ms packets, the last one padded: the audio was
        // 95 000 samples after the pre-skip, not 95 688
        let bytes = writer.finish(Some(95_000)).unwrap();

        let packets = read_packets(&bytes).unwrap();
        assert_eq!(packets.len(), 102);
        for (index, got) in packets[2..].iter().enumerate() {
            assert_eq!(got.data, packet(index));
        }

        let pages = pages(&bytes);
        let last = pages.last().unwrap();
        assert!(last.is_eos());
        assert_eq!(last.granule(), 312 + 95_000);
        // a second a page: fifty packets of 960 on the first audio page, and
        // the other fifty on the last, the held packet joining the forty-nine
        // committed after the first page went out
        assert_eq!(pages.len(), 4);
        assert_eq!(pages[2].granule(), 48_000);
        assert_eq!(pages[2].lacing().len(), 50);
        assert_eq!(pages[3].lacing().len(), 50);
        // the player's arithmetic: playable length is the last granule less
        // the pre-skip, and what the last page trims is what its packets add
        // up to less what its granule advanced by
        assert_eq!(last.granule() - 312, 95_000);
        assert_eq!(
            50 * 960 - (last.granule() - pages[2].granule()),
            96_000 - 312 - 95_000
        );
    }

    #[test]
    fn without_a_length_every_decoded_sample_is_kept() {
        let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        writer.write_packet(&packet(0), 960).unwrap();
        writer.write_packet(&packet(1), 2_880).unwrap();
        writer.write_packet(&packet(2), 120).unwrap();
        let bytes = writer.finish(None).unwrap();
        assert_eq!(pages(&bytes).last().unwrap().granule(), 3_960);
    }

    #[test]
    fn pages_go_out_once_they_hold_the_configured_duration() {
        let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        writer.set_max_page_duration(100).unwrap();
        let headers = writer.get_ref().len();
        // four 20 ms packets committed, a fifth held: nothing yet
        for index in 0..5 {
            writer.write_packet(&packet(index), 960).unwrap();
        }
        assert_eq!(writer.get_ref().len(), headers);
        // the sixth commits the fifth, which makes 100 ms: out it goes
        writer.write_packet(&packet(5), 960).unwrap();
        assert!(writer.get_ref().len() > headers);
        for index in 6..23 {
            writer.write_packet(&packet(index), 960).unwrap();
        }
        let bytes = writer.finish(None).unwrap();
        let granules: Vec<u64> = pages(&bytes)[2..].iter().map(Page::granule).collect();
        assert_eq!(granules, [4_800, 9_600, 14_400, 19_200, 22_080]);
    }

    #[test]
    fn flush_writes_the_page_being_filled_but_keeps_the_last_packet() {
        let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        writer.write_packet(&packet(0), 960).unwrap();
        writer.write_packet(&packet(1), 960).unwrap();
        writer.flush().unwrap();
        let bytes = writer.get_ref().clone();
        let flushed = pages(&bytes);
        assert_eq!(flushed.len(), 3);
        assert_eq!(flushed[2].granule(), 960);
        writer.flush().unwrap();
        assert_eq!(writer.get_ref().len(), bytes.len(), "nothing more to flush");
        // the page just written bounds the trimming from below
        let error = writer.finish(Some(960 - 312 - 1)).unwrap_err();
        assert!(matches!(
            error,
            Error::Length {
                min: 648,
                max: 1_608,
                ..
            }
        ));
    }

    #[test]
    fn the_last_page_cannot_extend_the_audio_or_trim_into_an_earlier_page() {
        let run = |length: u64| {
            let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
            writer.set_max_page_duration(20).unwrap();
            writer.write_packet(&packet(0), 960).unwrap();
            writer.write_packet(&packet(1), 960).unwrap();
            // the first packet is on a page of its own, ending at 960
            writer.finish(Some(length))
        };
        assert!(matches!(
            run(1_920 - 312 + 1),
            Err(Error::Length {
                requested: 1_609,
                min: 648,
                max: 1_608
            })
        ));
        assert!(matches!(run(647), Err(Error::Length { .. })));
        // both ends are expressible
        let bytes = run(1_608).unwrap();
        assert_eq!(pages(&bytes).last().unwrap().granule(), 1_920);
        let bytes = run(648).unwrap();
        assert_eq!(pages(&bytes).last().unwrap().granule(), 960);
    }

    #[test]
    fn a_page_whose_segment_table_fills_goes_out_early_and_bounds_the_trim() {
        let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        writer.set_max_page_duration(10_000).unwrap();
        // a thousand octets is four lacing values: sixty-three packets fill
        // 252 of the 255, and the sixty-fourth spills onto a new page
        let big = vec![0x5A_u8; 1_000];
        for _ in 0..65 {
            writer.write_packet(&big, 960).unwrap();
        }
        // packet 64 is committed and started the second page; the first page
        // ends inside it at 63 packets
        let error = writer.finish(Some(0)).unwrap_err();
        assert!(matches!(
            error,
            Error::Length {
                min: 60_168,
                max: 62_088,
                ..
            }
        ));

        let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        writer.set_max_page_duration(10_000).unwrap();
        for _ in 0..65 {
            writer.write_packet(&big, 960).unwrap();
        }
        let bytes = writer.finish(Some(60_168)).unwrap();
        let pages = pages(&bytes);
        assert_eq!(pages.len(), 4);
        assert_eq!(pages[2].granule(), 63 * 960);
        assert_eq!(pages[2].lacing().len(), 255);
        assert!(pages[3].is_continued());
        assert_eq!(pages[3].granule(), 63 * 960);
        assert_eq!(read_packets(&bytes).unwrap().len(), 67);
    }

    #[test]
    fn a_last_packet_that_fills_the_segment_table_cannot_trim_behind_the_page_it_forces_out() {
        let run = |length: u64| {
            let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
            writer.set_max_page_duration(10_000).unwrap();
            // sixty-three packets of four lacing values each take 252 of the
            // 255; the sixty-fourth, held back for the end, needs four more,
            // so writing it at the end sends out a page ending at 63 * 960
            let big = vec![0x5A_u8; 1_000];
            for _ in 0..64 {
                writer.write_packet(&big, 960).unwrap();
            }
            writer.finish(Some(length))
        };
        assert!(matches!(
            run(0),
            Err(Error::Length {
                requested: 0,
                min: 60_168,
                max: 61_128
            })
        ));
        let bytes = run(60_168).unwrap();
        let pages = pages(&bytes);
        assert_eq!(pages.len(), 4);
        assert_eq!(pages[2].granule(), 63 * 960);
        assert_eq!(pages[3].granule(), 63 * 960);
        assert!(pages[3].is_eos());
        assert_eq!(read_packets(&bytes).unwrap().len(), 66);
    }

    #[test]
    fn a_stream_without_audio_has_no_length_to_give() {
        let writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        assert!(matches!(
            writer.finish(Some(1)),
            Err(Error::Length { requested: 1, .. })
        ));
        let writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        assert!(writer.finish(Some(0)).is_ok());
    }

    #[test]
    fn only_packets_an_opus_encoder_could_produce_are_taken() {
        let mut writer = Writer::new(Vec::new(), &head(), &OpusTags::new(), 7).unwrap();
        assert!(matches!(
            writer.write_packet(&[], 960),
            Err(Error::EmptyPacket)
        ));
        for samples in [0, 100, 121, 5_880, 6_000] {
            assert!(
                matches!(
                    writer.write_packet(&[0xFC], samples),
                    Err(Error::Duration { samples: s }) if s == samples
                ),
                "{samples}"
            );
        }
        for samples in [120, 240, 480, 960, 1_920, 2_880, 5_760] {
            writer.write_packet(&[0xFC], samples).unwrap();
        }
        assert_eq!(writer.granule_position(), 12_360);
        assert!(matches!(
            writer.set_max_page_duration(0),
            Err(Error::PageDuration)
        ));
        assert_eq!(DEFAULT_MAX_PAGE_MS, 1_000);
    }

    #[test]
    fn a_failing_sink_is_reported() {
        #[derive(Debug)]
        struct Broken;
        impl std::io::Write for Broken {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk gone"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let error = Writer::new(Broken, &head(), &OpusTags::new(), 7).unwrap_err();
        assert!(matches!(error, Error::Io(_)));
        assert!(error.to_string().contains("disk gone"));
    }
}
