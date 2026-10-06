// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Recording a call: where a path becomes a file, and who closes it.
//!
//! Everything below this boundary writes to a sink it was handed and opens
//! nothing. That is deliberate and it is why recording is reachable from a
//! headless agent, from a test that records into memory, and from here. What is
//! left over is the one decision a sans-I/O tree cannot make for itself — which
//! file — and this is where it is made.
//!
//! # Who owns the handle
//!
//! The media session does, and therefore the stack does. C never sees the file:
//! it hands over a path and gets a status, and from then on the recording is a
//! property of the call the same way the codec is. A caller cannot leak it,
//! cannot close it underneath the stack, and has nothing to free.
//!
//! That leaves one question, and it is the whole of the ownership problem here:
//! a WAVE header carries two lengths that are not known until the recording
//! stops, so a file whose recorder was dropped rather than closed has zeroes
//! in them. The audio is all there and any editor repairs it, but nobody should
//! have to.
//!
//! So there are three ways a recording ends and all three close it properly:
//!
//! - [`sipral_media_record_stop`], which is the ordinary one;
//! - the call ending, where the engine stops the recording before it lets the
//!   stream go;
//! - the stack being destroyed, including from inside the event callback, where
//!   what the poll is still holding is closed as it is dropped.
//!
//! The third is the one that has to be arranged rather than inherited, and the
//! media engine arranges it as it is dropped: destroying a stack mid-recording
//! leaves a playable file, not a repair job. Nothing can be done about a process that
//! dies, and nothing here pretends otherwise.
//!
//! A process that dies cannot finish anything, so a recording is checkpointed
//! as it goes — every five seconds unless `sipral_recording_options_t` says
//! otherwise — and what a crash leaves plays up to the last checkpoint: a WAVE
//! file whose header states the audio written by then, with what came after
//! it in the file past that length, or an Ogg stream of whole pages without
//! the page that marks its end.
//!
//! # What is written
//!
//! By [`sipral_media_record_start`]: RIFF/WAVE, linear 16-bit PCM, one
//! channel, at `sipral_media_info_t::sample_rate` — both directions mixed
//! into one file, which is what a recording of a conversation is for. By
//! [`sipral_media_record_start_with`]: what [`SipralRecordingOptions`] says —
//! two channels, this end left and the far end right; Ogg Opus; a rate of the
//! file's own. Either way the file keeps its rate when a re-negotiation moves
//! the call to a codec at another one. An existing file at that path is
//! replaced: a recording is named by the caller, and a stack that refused
//! would be a stack that loses the recording rather than the old one.

use std::ffi::c_char;
use std::fs::File;
use std::time::Duration;

use sipral::{RecordingFormat, RecordingLayout, RecordingOptions};

use crate::abi::{Number, codes, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::{media_failed, with_media};
use crate::status::SipralStatus;
use crate::text::required_text;
use crate::versioned::{Versioned, read_versioned};

codes! {
    /// The file format of a recording. Names for
    /// `sipral_recording_options_t::format`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRecordingFormat: u32 {
        /// Sixteen-bit PCM in RIFF/WAVE, becoming RF64 past four gibibytes.
        Wav = 0,
        /// Opus in Ogg (RFC 7845), where `SIPRAL_FEATURE_OPUS` says the build
        /// has the encoder; `SIPRAL_STATUS_NOT_SUPPORTED` where it does not.
        OggOpus = 1,
    }
}

codes! {
    /// How the two directions of a call share a recording. Names for
    /// `sipral_recording_options_t::layout`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralRecordingLayout: u32 {
        /// One channel: both directions, each at half level, summed.
        Mixed = 0,
        /// Two channels: this end on the left, the far end on the right.
        Stereo = 1,
    }
}

record! {
    /// How [`sipral_media_record_start_with`] writes a recording. Zero in
    /// every member but `size` is [`sipral_media_record_start`]'s file.
    ///
    /// Set `size` to `sizeof(sipral_recording_options_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralRecordingOptions {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// A [`SipralRecordingFormat`].
        pub format: Number<SipralRecordingFormat>,
        /// A [`SipralRecordingLayout`].
        pub layout: Number<SipralRecordingLayout>,
        /// The rate the file is written at, in hertz, or zero for the rate the
        /// call's codec hears at when the recording starts (48 kHz for Ogg
        /// Opus on a call at a rate Opus does not take). WAV takes 8000 to
        /// 48000; Ogg Opus takes 8000, 12000, 16000, 24000 and 48000.
        pub sample_rate: u32,
        /// An Ogg Opus recording's bitrate in bits a second, all channels
        /// together, or zero for libopus's own choice. Not read for WAV.
        pub bitrate: u32,
        /// How often, in milliseconds, what has been written is made to
        /// survive a crash, or zero for every five seconds.
        pub checkpoint_ms: u32,
        /// Zero. Rounds the struct up to a whole multiple of its alignment on
        /// every target, so that a member a later version appends starts at or
        /// past the length a caller built against this header declares, never
        /// in padding inside it. Set it to zero; the library reads nothing from
        /// it.
        pub reserved: u32,
    }
}

// Safety: the trait's contract. Integers only, and all-zero is a valid value
// of each: it is the plain recording.
unsafe impl Versioned for SipralRecordingOptions {
    const NAME: &'static str = "sipral_recording_options";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralRecordingOptions, reserved);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// What a C recording's options ask for, or why they cannot be taken.
pub(crate) fn options_of(options: &SipralRecordingOptions) -> Result<RecordingOptions, Fail> {
    let defaults = RecordingOptions::default();
    let format = match options.format {
        0 => RecordingFormat::Wav,
        1 => ogg_opus()?,
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("format is {other}; it is 0 for WAV or 1 for Ogg Opus"),
            ));
        }
    };
    let layout = match options.layout {
        0 => RecordingLayout::Mixed,
        1 => RecordingLayout::Stereo,
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!("layout is {other}; it is 0 for mixed or 1 for stereo"),
            ));
        }
    };
    Ok(RecordingOptions {
        format,
        layout,
        sample_rate: (options.sample_rate != 0).then_some(options.sample_rate),
        bitrate: (options.bitrate != 0).then_some(options.bitrate),
        checkpoint: if options.checkpoint_ms == 0 {
            defaults.checkpoint
        } else {
            Duration::from_millis(u64::from(options.checkpoint_ms))
        },
    })
}

/// Ogg Opus, where the facade this crate sits on linked the encoder — asked
/// of the facade's own capabilities, since a Cargo feature belongs to the
/// crate that declares it.
fn ogg_opus() -> Result<RecordingFormat, Fail> {
    RecordingFormat::ogg_opus().ok_or_else(|| {
        fail(
            SipralStatus::NotSupported,
            "this build has no Opus encoder to write Ogg Opus with",
        )
    })
}

/// Make the file and start the recording in it, with this call's media held.
fn start(media: SipralHandle, path: &str, options: &RecordingOptions) -> Result<(), Fail> {
    with_media(media, |session, _| {
        // the call is looked at before the file is made, so a handle that
        // names nothing does not leave an empty recording behind
        if session.is_recording() {
            return Err(fail(
                SipralStatus::WrongState,
                "this call is already being recorded",
            ));
        }
        let file = File::create(path).map_err(|error| {
            fail(
                SipralStatus::InvalidArgument,
                format!("path is {path:?}, which cannot be written: {error}"),
            )
        })?;
        session
            .start_recording_with(Box::new(file), options)
            .map_err(|error| media_failed(&error))
    })
}

entry! {
    /// Start recording this call to `path`.
    ///
    /// Both directions, mixed, as WAVE. It can be started and stopped as often
    /// as the person on the phone presses the button, and each recording is a
    /// file of its own: a path written to twice would have two headers in it.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call whose media has ended and for one
    /// already being recorded — two writers on one stream would interleave
    /// frames into both files. `SIPRAL_STATUS_INVALID_ARGUMENT` when the file
    /// system refuses the path, with what it said in the last error.
    ///
    /// The file is made with this call's media held, so this call's audio
    /// waits for the file system to answer and no other call's does.
    ///
    /// # Safety
    ///
    /// `path` must be readable for `path_len` bytes.
    fn sipral_media_record_start(media: SipralHandle, path: *const c_char, path_len: usize) {
        let path = unsafe { required_text(path, path_len, "path") }?;
        start(media, path, &RecordingOptions::default())
    }
}

entry! {
    /// Start recording this call to `path`, written as `options` say: WAV or
    /// Ogg Opus, mixed or stereo with this end on the left, at a rate of the
    /// file's own. Everything else is [`sipral_media_record_start`]'s,
    /// which is this with every option zero.
    ///
    /// `SIPRAL_STATUS_INVALID_ARGUMENT` for options no file can be written
    /// with and for a path the file system refuses, and
    /// `SIPRAL_STATUS_NOT_SUPPORTED` for Ogg Opus in a build with no Opus.
    /// `SIPRAL_STATUS_RECORDING_FAILED` when the file was made and would not
    /// take its header.
    ///
    /// # Safety
    ///
    /// `path` must be readable for `path_len` bytes, and `options` must point
    /// at a `sipral_recording_options_t` whose `size` member says how long
    /// it is.
    fn sipral_media_record_start_with(
        media: SipralHandle,
        path: *const c_char,
        path_len: usize,
        options: *const SipralRecordingOptions,
    ) {
        let path = unsafe { required_text(path, path_len, "path") }?;
        let options = options_of(&unsafe { read_versioned(options) }?)?;
        // refused before the file is made, so options no file can be written
        // with leave nothing behind
        options.rate_for(8_000).map_err(|error| media_failed(&error))?;
        start(media, path, &options)
    }
}

entry! {
    /// Stop it, and close the file.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` when nothing is being recorded. A failure
    /// here leaves a file with all of the audio in it and zeroes in the two
    /// header fields, which is recoverable and is said rather than hidden.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle value.
    fn sipral_media_record_stop(media: SipralHandle) {
        with_media(media, |session, _| {
            session
                .stop_recording()
                .map_err(|error| media_failed(&error))
        })
    }
}

entry! {
    /// Whether a recording is running on this call, and how much audio it has
    /// taken. Either out parameter may be null.
    ///
    /// The length is of the audio written, not of the file: the header in front
    /// of it is not a recording of anything.
    ///
    /// # Safety
    ///
    /// `out_recording` must point at one `uint32_t` or be null, and
    /// `out_recorded_ms` at one `uint64_t` or be null.
    fn sipral_media_record_state(
        media: SipralHandle,
        out_recording: *mut u32,
        out_recorded_ms: *mut u64,
    ) {
        let (recording, taken) = with_media(media, |session, _| {
            let taken = session
                .recorded()
                .map_or(0, |span| u64::try_from(span.as_millis()).unwrap_or(u64::MAX));
            Ok((session.is_recording(), taken))
        })?;
        if !out_recording.is_null() {
            unsafe { out_recording.write(u32::from(recording)) };
        }
        if !out_recorded_ms.is_null() {
            unsafe { out_recorded_ms.write(taken) };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{sipral_media_record_start, sipral_media_record_state, sipral_media_record_stop};
    use crate::call::tests::{connected, hangup, media_call};
    use crate::error::last_error_text;
    use crate::event::SipralEventKind;
    use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
    use crate::media::sipral_call_media;
    use crate::media::tests::{FRAME, capture_one, media_of, play_one, release};
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::Observed;
    use crate::status::SipralStatus;
    use std::ffi::c_char;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A path in the platform's temporary directory that no other test in this
    /// binary will pick. Tests run on threads of one process, so the counter is
    /// enough and the process id keeps two runs apart.
    fn scratch(what: &str) -> PathBuf {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "sipral-{what}-{}-{ordinal}.wav",
            std::process::id()
        ))
    }

    fn start(media: SipralHandle, path: &Path) -> SipralStatus {
        let written = path.to_string_lossy().into_owned();
        unsafe {
            sipral_media_record_start(media, written.as_ptr().cast::<c_char>(), written.len())
        }
    }

    fn state_of(media: SipralHandle) -> (u32, u64) {
        let mut recording = u32::MAX;
        let mut taken = u64::MAX;
        let status =
            unsafe { sipral_media_record_state(media, &raw mut recording, &raw mut taken) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        (recording, taken)
    }

    /// The header a recording's file starts with: RIFF, a `JUNK` chunk held
    /// for RF64, `fmt ` and the data chunk's own header.
    const HEADER: usize = 80;

    /// Where the sampling rate sits in it.
    const RATE_AT: usize = 60;

    /// Where the channel count sits.
    const CHANNELS_AT: usize = 58;

    /// Where the data chunk's length sits.
    const DATA_LENGTH_AT: usize = 76;

    /// One of the little-endian fields of a WAVE header.
    fn field(wav: &[u8], at: usize, len: usize) -> u32 {
        let mut value = 0_u32;
        for (index, byte) in wav[at..at + len].iter().enumerate() {
            value |= u32::from(*byte) << (index * 8);
        }
        value
    }

    /// Put a few frames of a conversation through the call, so that there is
    /// something in the file to have a length.
    fn talk(media: SipralHandle, frames: usize) {
        for _ in 0..frames {
            play_one(media);
            capture_one(media, &[4_000; FRAME]);
        }
    }

    #[test]
    fn a_recording_starts_stops_and_says_so_while_it_runs() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let path = scratch("started");

        assert_eq!(state_of(media), (0, 0), "nothing yet");
        assert_eq!(
            start(media, &path),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        talk(media, 50);
        let (recording, taken) = state_of(media);
        assert_eq!(recording, 1);
        assert_eq!(taken, 1_000, "fifty frames of twenty milliseconds");

        assert_eq!(unsafe { sipral_media_record_stop(media) }, SipralStatus::Ok);
        assert_eq!(state_of(media), (0, 0));
        let died = observed.of(SipralEventKind::RecordingStopped);
        assert!(
            died.is_empty(),
            "the recording stopped by itself after {:?} milliseconds",
            died.iter()
                .map(|heard| heard.recorded_ms)
                .collect::<Vec<_>>()
        );
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);

        let wav = std::fs::read(&path).expect("the recording is a file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(&wav[0..4], b"RIFF");
        assert_eq!(&wav[8..12], b"WAVE");
        assert_eq!(
            field(&wav, RATE_AT, 4),
            8_000,
            "the rate the codec hears at"
        );
        assert_eq!(
            field(&wav, CHANNELS_AT, 2),
            1,
            "one channel, both directions"
        );
        assert_eq!(
            field(&wav, DATA_LENGTH_AT, 4),
            50 * 160 * 2,
            "the audio that was written"
        );
    }

    /// The first half of the ownership question: a recording nobody stopped,
    /// on a call that ended. The engine closes it before it lets the stream go,
    /// so the file is playable and the handle is gone.
    #[test]
    fn a_call_that_ends_closes_the_recording_it_was_carrying() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let path = scratch("hungup");
        assert_eq!(start(media, &path), SipralStatus::Ok);
        talk(media, 10);

        hangup(stack, call, 9_000);
        let mut recording = u32::MAX;
        assert_eq!(
            unsafe { sipral_media_record_state(media, &raw mut recording, std::ptr::null_mut()) },
            SipralStatus::WrongState,
            "the handle of a call that ended still answered as if it were recording"
        );
        assert_eq!(recording, u32::MAX, "nothing was written");
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);

        let wav = std::fs::read(&path).expect("the recording is a file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            field(&wav, DATA_LENGTH_AT, 4),
            10 * 160 * 2,
            "the data length was patched, so a player will open it"
        );
        assert_eq!(
            usize::try_from(field(&wav, 4, 4)).unwrap(),
            wav.len() - 8,
            "and so was the RIFF length"
        );
    }

    /// The other half, and the one that has to be arranged: the stack is
    /// destroyed with a recording running. Nothing asked the session to stop,
    /// and the file still ends up playable, because the header is patched as
    /// the stack is dropped.
    #[test]
    fn destroying_a_stack_mid_recording_still_leaves_a_playable_file() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let path = scratch("destroyed");
        assert_eq!(start(media, &path), SipralStatus::Ok);
        talk(media, 25);

        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
        assert_eq!(
            unsafe { sipral_media_record_stop(media) },
            SipralStatus::WrongState,
            "the handle outlived its stack and still reached the session"
        );
        release(media);

        let wav = std::fs::read(&path).expect("the recording is a file");
        let _ = std::fs::remove_file(&path);
        let audio = 25 * 160 * 2;
        assert_eq!(wav.len(), HEADER + audio);
        assert_eq!(
            field(&wav, DATA_LENGTH_AT, 4),
            u32::try_from(audio).unwrap()
        );
        assert_eq!(
            usize::try_from(field(&wav, 4, 4)).unwrap(),
            HEADER - 8 + audio,
            "zeroes here are a file a player calls corrupt"
        );
    }

    fn start_with(
        media: SipralHandle,
        path: &Path,
        options: &super::SipralRecordingOptions,
    ) -> SipralStatus {
        let written = path.to_string_lossy().into_owned();
        unsafe {
            super::sipral_media_record_start_with(
                media,
                written.as_ptr().cast::<c_char>(),
                written.len(),
                options,
            )
        }
    }

    fn options() -> super::SipralRecordingOptions {
        super::SipralRecordingOptions {
            reserved: 0,
            size: size_of::<super::SipralRecordingOptions>(),
            format: 0,
            layout: 0,
            sample_rate: 0,
            bitrate: 0,
            checkpoint_ms: 0,
        }
    }

    /// Stereo at a rate of the file's own: this end on the left, the far
    /// end on the right, and twice the samples of the call's own rate.
    #[test]
    fn a_stereo_recording_at_its_own_rate_is_what_the_options_asked_for() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let path = scratch("stereo");
        let asked = super::SipralRecordingOptions {
            layout: super::SipralRecordingLayout::Stereo as u32,
            sample_rate: 16_000,
            ..options()
        };
        assert_eq!(
            start_with(media, &path, &asked),
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        talk(media, 25);
        assert_eq!(unsafe { sipral_media_record_stop(media) }, SipralStatus::Ok);
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);

        let wav = std::fs::read(&path).expect("the recording is a file");
        let _ = std::fs::remove_file(&path);
        assert_eq!(field(&wav, CHANNELS_AT, 2), 2);
        assert_eq!(field(&wav, RATE_AT, 4), 16_000);
        let frames = (wav.len() - HEADER) / 4;
        // half a second at 16 kHz, less what the converter still held
        assert!(frames.abs_diff(8_000) <= 64, "{frames} frames");
        // the microphone's constant is this end's, on the left
        let left: Vec<i16> = wav[HEADER..]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|&[l0, l1, _, _]| i16::from_le_bytes([l0, l1]))
            .collect();
        assert!(
            left.iter()
                .skip(200)
                .take(1_000)
                .all(|&sample| sample.abs_diff(4_000) < 200)
        );
    }

    /// Ogg Opus where the build has the encoder, and a clear refusal where it
    /// does not; either way nothing is left behind by options no file can be
    /// written with.
    #[test]
    fn ogg_opus_is_written_where_this_build_can_and_bad_options_leave_no_file() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let path = scratch("ogg");
        let ogg = super::SipralRecordingOptions {
            format: super::SipralRecordingFormat::OggOpus as u32,
            ..options()
        };
        let status = start_with(media, &path, &ogg);
        if sipral::Capabilities::of_this_build().opus {
            assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
            talk(media, 25);
            assert_eq!(unsafe { sipral_media_record_stop(media) }, SipralStatus::Ok);
            let bytes = std::fs::read(&path).expect("the recording is a file");
            assert_eq!(&bytes[..4], b"OggS");
            assert!(bytes.windows(8).any(|window| window == b"OpusHead"));
        } else {
            assert_eq!(status, SipralStatus::NotSupported);
        }
        let _ = std::fs::remove_file(&path);

        for (bad, what) in [
            (
                super::SipralRecordingOptions {
                    sample_rate: 44_100,
                    ..ogg
                },
                "44100",
            ),
            (
                super::SipralRecordingOptions {
                    format: 7,
                    ..options()
                },
                "format",
            ),
            (
                super::SipralRecordingOptions {
                    layout: 9,
                    ..options()
                },
                "layout",
            ),
            (
                super::SipralRecordingOptions {
                    sample_rate: 96_000,
                    ..options()
                },
                "96000",
            ),
        ] {
            let nowhere = scratch("refused");
            let status = start_with(media, &nowhere, &bad);
            if bad.format == 1 && !sipral::Capabilities::of_this_build().opus {
                assert_eq!(status, SipralStatus::NotSupported);
            } else {
                assert_eq!(status, SipralStatus::InvalidArgument, "{what}");
                assert!(last_error_text().contains(what), "{}", last_error_text());
            }
            assert!(!nowhere.exists(), "{what} left a file behind");
        }
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    #[test]
    fn two_recordings_at_once_are_refused_rather_than_interleaved() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let first = scratch("first");
        let second = scratch("second");
        assert_eq!(start(media, &first), SipralStatus::Ok);
        assert_eq!(start(media, &second), SipralStatus::WrongState);
        assert!(
            !second.exists(),
            "the second file was not made, so nothing was left behind"
        );
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
        let _ = std::fs::remove_file(&first);
    }

    #[test]
    fn stopping_a_recording_that_is_not_running_says_so() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        assert_eq!(
            unsafe { sipral_media_record_stop(media) },
            SipralStatus::WrongState
        );
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    #[test]
    fn a_path_the_file_system_refuses_is_said_and_the_call_carries_on() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        let nowhere = std::env::temp_dir()
            .join("sipral-no-such-directory")
            .join("x.wav");
        assert_eq!(start(media, &nowhere), SipralStatus::InvalidArgument);
        assert!(last_error_text().contains("sipral-no-such-directory"));
        assert_eq!(state_of(media), (0, 0), "and nothing is recording");

        let path = scratch("after");
        assert_eq!(
            start(media, &path),
            SipralStatus::Ok,
            "the call is untouched by a recording that could not start"
        );
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
        let _ = std::fs::remove_file(&path);
    }

    /// Recording is a property of a call's media, so a call this stack
    /// describes nothing for has no media handle to put a tap on, and a handle
    /// nobody minted records nothing.
    #[test]
    fn a_call_with_no_media_cannot_be_recorded() {
        let mut observed = Observed::default();
        let (stack, call) = connected(&mut observed);
        let path = scratch("unmanaged");
        let mut media = SIPRAL_HANDLE_NONE;
        assert_eq!(
            unsafe { sipral_call_media(stack, call, &raw mut media) },
            SipralStatus::WrongState
        );
        assert_eq!(media, SIPRAL_HANDLE_NONE, "no handle was written");
        assert_eq!(start(media, &path), SipralStatus::InvalidHandle);
        assert!(!path.exists());
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }
}
