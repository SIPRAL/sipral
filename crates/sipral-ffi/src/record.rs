// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

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
//! # What is written
//!
//! RIFF/WAVE, linear 16-bit PCM, one channel, at
//! `sipral_media_info_t::sample_rate` — both directions mixed into one file,
//! which is what a recording of a conversation is for. An existing file at that
//! path is replaced: a recording is named by the caller, and a stack that
//! refused would be a stack that loses the recording rather than the old one.

use std::ffi::c_char;
use std::fs::File;

use crate::error::{entry, fail};
use crate::handle::SipralHandle;
use crate::media::{media_failed, with_media};
use crate::status::SipralStatus;
use crate::text::required_text;

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
                .start_recording(Box::new(file))
                .map_err(|error| media_failed(&error))
        })
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
        assert_eq!(field(&wav, 24, 4), 8_000, "the rate the codec hears at");
        assert_eq!(
            field(&wav, 40, 4),
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
            field(&wav, 40, 4),
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
        assert_eq!(wav.len(), 44 + audio);
        assert_eq!(field(&wav, 40, 4), u32::try_from(audio).unwrap());
        assert_eq!(
            usize::try_from(field(&wav, 4, 4)).unwrap(),
            44 - 8 + audio,
            "zeroes here are a file a player calls corrupt"
        );
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
