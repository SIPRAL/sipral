// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a call carries inside its audio, from C.
//!
//! Three settings, each per call and each reachable before the call has any
//! media: the settings live with the call in the engine and reach its media
//! when there is some, so an application sets them straight after
//! `sipral_call_place` — or on `SIPRAL_EVENT_KIND_INCOMING_CALL`, before it
//! answers — and never has to catch the moment media starts.
//!
//! - [`sipral_call_dtmf_detection`]: when keypad digits are listened for in
//!   the far end's audio. The stack's default is
//!   `sipral_stack_config_t::dtmf_detection`.
//! - [`sipral_call_detect_progress`]: call-progress tones on early media,
//!   who answered, and the machine's beep, reported as
//!   `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`.
//! - [`sipral_call_consent_tone`]: a beep while the call is recorded.
//!
//! A digit written into the audio is a form of `sipral_call_send_dtmf`
//! (`SIPRAL_DTMF_IN_BAND`), and a recording's format is
//! `sipral_media_record_start_with`'s; neither is here.
//!
//! Every struct here starts out meaning "the defaults" when it is zeroed, so
//! a caller names only what it wants to change. `docs/05-media.md` says what
//! each default is and why.

use std::time::Duration;

use sipral::{
    AmdConfig, BeepConfig, ConsentTone, DtmfDetection, ProgressConfig, ProgressDetection,
    ToneRegion,
};

use crate::abi::{codes, record};
use crate::error::{Fail, entry, fail};
use crate::handle::SipralHandle;
use crate::media::{media_failed, toggled};
use crate::stack::{StackState, handle_failed, with_stack};
use crate::status::SipralStatus;
use crate::versioned::{Versioned, read_versioned};

codes! {
    /// When a call listens for keypad digits in the far end's audio. Names
    /// for `sipral_stack_config_t::dtmf_detection` and
    /// [`sipral_call_dtmf_detection`]'s `mode`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralDtmfDetection: u32 {
        /// On a call whose negotiation settled on no telephone event payload
        /// type: the far end then has no other way to send a digit. Zero, so
        /// that a stack that says nothing gets it.
        Auto = 0,
        /// Never. Digits arrive only as RFC 4733 events or by INFO.
        Off = 1,
        /// On every call. A press the far end sends both as an event and in
        /// the audio is reported once, as the event.
        Always = 2,
    }
}

codes! {
    /// Whose call-progress tones to listen for. Names for
    /// `sipral_progress_config_t::region`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SipralToneRegion: u32 {
        /// The 425 Hz tones common to the CEPT administrations.
        Europe = 0,
        /// The United States and Canada.
        NorthAmerica = 1,
        /// The United Kingdom.
        UnitedKingdom = 2,
    }
}

record! {
    /// How [`sipral_call_detect_progress`] listens. Zero in any member but
    /// `size` is that member's default.
    ///
    /// Set `size` to `sizeof(sipral_progress_config_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralProgressConfig {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// A `SipralToggle`: on (the default) listens with what follows,
        /// off stops listening and reads nothing else.
        pub listen: u32,
        /// A [`SipralToneRegion`]. Europe by default.
        pub region: u32,
        /// A `SipralToggle`: whether to decide who answered. On by default.
        pub answering_machine: u32,
        /// A `SipralToggle`: whether to listen for the beep after a verdict
        /// of a machine. On by default.
        pub beep: u32,
        /// How long after the verdict to listen for the beep. Thirty
        /// seconds by default.
        pub beep_window_ms: u32,
        /// The longest silence after answer before the verdict is not sure.
        /// 3000 by default.
        pub max_initial_silence_ms: u32,
        /// The longest greeting a person gives. 1600 by default.
        pub max_greeting_ms: u32,
        /// The silence after a greeting that says a person is waiting. 700
        /// by default.
        pub silence_after_greeting_ms: u32,
        /// The most words a person's greeting has. 4 by default.
        pub max_words: u32,
        /// The shortest run of speech that is a word. 120 by default.
        pub min_word_ms: u32,
        /// The shortest silence that separates two words. 60 by default.
        pub min_word_gap_ms: u32,
        /// The longest the decision may take, from answer. 6000 by default.
        pub max_decision_ms: u32,
        /// How far above the noise floor a frame must be to be speech, in
        /// dB. 6 by default.
        pub min_speech_above_floor_db: u32,
        /// The shortest beep. 120 by default.
        pub beep_min_ms: u32,
        /// The longest beep: anything held longer is a tone, not a beep.
        /// This build's own default unless set.
        pub beep_max_ms: u32,
        /// How many whole cycles of a repeating cadence are heard before the
        /// tone is reported, from one to four. One by default.
        pub tone_cycles: u32,
    }
}

// Safety: the trait's contract. Integers only, and all-zero is a valid value
// of each: it is the defaults.
unsafe impl Versioned for SipralProgressConfig {
    const NAME: &'static str = "sipral_progress_config";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralProgressConfig, tone_cycles);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

record! {
    /// The beep [`sipral_call_consent_tone`] plays while a call is recorded.
    /// Zero in any member but `size` is that member's default.
    ///
    /// Set `size` to `sizeof(sipral_consent_tone_t)` before the call.
    #[derive(Clone, Copy, Debug)]
    pub struct SipralConsentTone {
        /// `sizeof` this struct, as the caller's header declares it.
        pub size: usize,
        /// A `SipralToggle`: on (the default) beeps as what follows says,
        /// off plays no tone and reads nothing else.
        pub enabled: u32,
        /// Its frequency, from 300 to 3400 Hz. 1400 by default.
        pub frequency_hz: u32,
        /// How far below 0 dBm0 it sounds, from 3 to 40 dB: 18 is a beep at
        /// −18 dBm0, the default.
        pub attenuation_db: u32,
        /// How long each beep lasts, from 50 to 2000 ms. 200 by default.
        pub length_ms: u32,
        /// How often it repeats, start to start: longer than a beep and at
        /// most ten minutes. Fifteen seconds by default.
        pub interval_ms: u32,
        /// A `SipralToggle`: whether this end hears it too. On by default.
        pub local: u32,
    }
}

// Safety: the trait's contract. Integers only, and all-zero is a valid value
// of each: it is the defaults.
unsafe impl Versioned for SipralConsentTone {
    const NAME: &'static str = "sipral_consent_tone";
    const PIN: crate::versioned::Pin = crate::versioned::pin!(SipralConsentTone, local);

    fn set_declared_size(&mut self, bytes: usize) {
        self.size = bytes;
    }
}

/// A `dtmf_detection` value, or what the three are.
pub(crate) fn detection_of(value: u32, name: &'static str) -> Result<DtmfDetection, Fail> {
    match value {
        0 => Ok(DtmfDetection::Auto),
        1 => Ok(DtmfDetection::Off),
        2 => Ok(DtmfDetection::Always),
        other => Err(fail(
            SipralStatus::InvalidArgument,
            format!("{name} is {other}; it is 0 for auto, 1 for off or 2 for always"),
        )),
    }
}

/// `value`, or `default` for the zero that means "unset".
const fn or(value: u32, default: u32) -> u32 {
    if value == 0 { default } else { value }
}

/// What a progress configuration asks for, or why it cannot be taken.
fn progress_of(config: &SipralProgressConfig) -> Result<Option<ProgressDetection>, Fail> {
    if !toggled(config.listen, "listen", true)? {
        return Ok(None);
    }
    let region = match config.region {
        0 => ToneRegion::Europe,
        1 => ToneRegion::NorthAmerica,
        2 => ToneRegion::UnitedKingdom,
        other => {
            return Err(fail(
                SipralStatus::InvalidArgument,
                format!(
                    "region is {other}; it is 0 for Europe, 1 for North America or 2 for the \
                     United Kingdom"
                ),
            ));
        }
    };
    if config.tone_cycles > 4 {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("tone_cycles is {}; it is one to four", config.tone_cycles),
        ));
    }
    let defaults = ProgressDetection::default();
    let amd = AmdConfig::default();
    let answering_machine =
        toggled(config.answering_machine, "answering_machine", true)?.then(|| AmdConfig {
            max_initial_silence_ms: or(config.max_initial_silence_ms, amd.max_initial_silence_ms),
            max_greeting_ms: or(config.max_greeting_ms, amd.max_greeting_ms),
            silence_after_greeting_ms: or(
                config.silence_after_greeting_ms,
                amd.silence_after_greeting_ms,
            ),
            max_words: or(config.max_words, amd.max_words),
            min_word_ms: or(config.min_word_ms, amd.min_word_ms),
            min_word_gap_ms: or(config.min_word_gap_ms, amd.min_word_gap_ms),
            max_decision_ms: or(config.max_decision_ms, amd.max_decision_ms),
            min_speech_above_floor_db: or(
                config.min_speech_above_floor_db,
                amd.min_speech_above_floor_db,
            ),
        });
    let beep = BeepConfig::default();
    let beep = toggled(config.beep, "beep", true)?.then(|| BeepConfig {
        min_ms: or(config.beep_min_ms, beep.min_ms),
        max_ms: or(config.beep_max_ms, beep.max_ms),
        ..beep
    });
    if let Some(limits) = beep
        && limits.min_ms > limits.max_ms
    {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!(
                "beep_min_ms is {} and beep_max_ms {}, so no beep can be heard",
                limits.min_ms, limits.max_ms
            ),
        ));
    }
    Ok(Some(ProgressDetection {
        region,
        tones: ProgressConfig {
            cycles: or(config.tone_cycles, defaults.tones.cycles),
            ..defaults.tones
        },
        answering_machine,
        beep,
        beep_window: if config.beep_window_ms == 0 {
            defaults.beep_window
        } else {
            Duration::from_millis(u64::from(config.beep_window_ms))
        },
    }))
}

/// What a consent tone asks for, or why it cannot be taken.
fn consent_of(tone: &SipralConsentTone) -> Result<Option<ConsentTone>, Fail> {
    if !toggled(tone.enabled, "enabled", true)? {
        return Ok(None);
    }
    let defaults = ConsentTone::default();
    let millis = |value: u32, default: Duration| {
        if value == 0 {
            default
        } else {
            Duration::from_millis(u64::from(value))
        }
    };
    // said in this struct's own terms rather than the level the facade
    // checks, which C never names
    let attenuation = or(tone.attenuation_db, defaults.level_dbm0.unsigned_abs());
    if !(3..=40).contains(&attenuation) {
        return Err(fail(
            SipralStatus::InvalidArgument,
            format!("attenuation_db is {attenuation}; it is 3 to 40"),
        ));
    }
    let chosen = ConsentTone {
        frequency_hz: or(tone.frequency_hz, defaults.frequency_hz),
        level_dbm0: -i32::try_from(attenuation).unwrap_or(40),
        length: millis(tone.length_ms, defaults.length),
        interval: millis(tone.interval_ms, defaults.interval),
        local: toggled(tone.local, "local", defaults.local)?,
    };
    chosen.check().map_err(|error| media_failed(&error))?;
    Ok(Some(chosen))
}

/// The call a handle names, when this stack describes its media; the three
/// settings here are about media this stack runs.
fn engine_call(state: &StackState, call: SipralHandle) -> Result<sipral_ua::CallHandle, Fail> {
    let id = state.calls.get(call).map_err(handle_failed)?;
    if !state.manages(id) {
        return Err(fail(
            SipralStatus::WrongState,
            "this call's media is not this stack's: it was not placed or answered with a media \
             address of its own",
        ));
    }
    Ok(id)
}

entry! {
    /// Listen for keypad digits in this call's far-end audio as `mode` says:
    /// a [`SipralDtmfDetection`]. Before the call has media as well as
    /// after, for the rest of the call.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call whose media this stack does
    /// not run.
    ///
    /// # Safety
    ///
    /// Safe to call with any handle values.
    fn sipral_call_dtmf_detection(stack: SipralHandle, call: SipralHandle, mode: u32) {
        let detection = detection_of(mode, "mode")?;
        with_stack(stack, |state| {
            let id = engine_call(state, call)?;
            state
                .engine
                .set_dtmf_detection(id, detection)
                .map_err(|error| media_failed(&error))
        })
    }
}

entry! {
    /// Listen for call progress on this call and decide who answers it, as
    /// `config` says, or stop with `config.listen` off. Meant for a call this
    /// stack placed, straight after `sipral_call_place`: the tones are
    /// listened for from the first frame of early media, and who answered is
    /// decided from the 2xx on. Each thing heard is a
    /// `SIPRAL_EVENT_KIND_PROGRESS_DETECTED`.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call whose media this stack does
    /// not run; `SIPRAL_STATUS_INVALID_ARGUMENT` for a value no detector
    /// takes, which changes nothing.
    ///
    /// # Safety
    ///
    /// `config` must point at a `sipral_progress_config_t` whose `size`
    /// member says how long it is.
    fn sipral_call_detect_progress(
        stack: SipralHandle,
        call: SipralHandle,
        config: *const SipralProgressConfig,
    ) {
        let config = unsafe { read_versioned(config) }?;
        let detection = progress_of(&config)?;
        with_stack(stack, |state| {
            let id = engine_call(state, call)?;
            state
                .engine
                .detect_progress(id, detection)
                .map_err(|error| media_failed(&error))
        })
    }
}

entry! {
    /// Beep on this call while it is recorded, as `tone` says, or play no
    /// tone with `tone.enabled` off. A recording already running starts
    /// beeping at once; one started later beeps from its first frame.
    ///
    /// `SIPRAL_STATUS_WRONG_STATE` for a call whose media this stack does
    /// not run; `SIPRAL_STATUS_INVALID_ARGUMENT`, naming the member, for a
    /// tone that is not a beep, which changes nothing.
    ///
    /// # Safety
    ///
    /// `tone` must point at a `sipral_consent_tone_t` whose `size` member
    /// says how long it is.
    fn sipral_call_consent_tone(
        stack: SipralHandle,
        call: SipralHandle,
        tone: *const SipralConsentTone,
    ) {
        let tone = unsafe { read_versioned(tone) }?;
        let chosen = consent_of(&tone)?;
        with_stack(stack, |state| {
            let id = engine_call(state, call)?;
            state
                .engine
                .set_consent_tone(id, chosen)
                .map_err(|error| media_failed(&error))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{
        SipralConsentTone, SipralDtmfDetection, SipralProgressConfig, sipral_call_consent_tone,
        sipral_call_detect_progress, sipral_call_dtmf_detection,
    };
    use crate::call::tests::{
        ANSWER, PEER_MEDIA, accepted, connected, deliver, managed_config, media_call, media_line,
        one, place, sent,
    };
    use crate::error::last_error_text;
    use crate::event::{SipralAmdVerdict, SipralDigitSource, SipralEventKind, SipralProgressKind};
    use crate::handle::SipralHandle;
    use crate::media::tests::{FRAME, arrive, media_of, play_one, release};
    use crate::stack::sipral_stack_destroy;
    use crate::stack::tests::{Observed, poll};
    use crate::status::SipralStatus;
    use sipral_media::g711::Law;
    use sipral_media::inband::dtmf::Digit;
    use sipral_media::inband::generate::{DtmfGenerator, DtmfTone};

    /// The far end's audio as the mu-law packets it would send, from
    /// sequence number `first` on.
    fn packets(pcm: &[i16], first: u16) -> Vec<Vec<u8>> {
        pcm.chunks(FRAME)
            .zip(first..)
            .map(|(frame, sequence)| {
                let mut out = vec![0x80, Law::Mu.payload_type()];
                out.extend_from_slice(&sequence.to_be_bytes());
                out.extend_from_slice(&(u32::from(sequence) * 160).to_be_bytes());
                out.extend_from_slice(&0x0BAD_CAFE_u32.to_be_bytes());
                let mut payload = [0_u8; FRAME];
                Law::Mu.encode_into(frame, &mut payload);
                out.extend_from_slice(&payload);
                out
            })
            .collect()
    }

    /// Hand the far end's audio to a call a frame at a time and play each
    /// frame out, then drain the events.
    fn hear(stack: SipralHandle, media: SipralHandle, pcm: &[i16], from_ms: u64) {
        let mut now = from_ms;
        for mut packet in packets(pcm, 100) {
            arrive(media, &mut packet, PEER_MEDIA, now);
            play_one(media);
            now += 20;
        }
        poll(stack, now);
    }

    fn digit(key: char) -> Vec<i16> {
        let mut pcm = vec![0_i16; 800];
        let mut generator = DtmfGenerator::with_tone_at(8_000, DtmfTone::default());
        generator.start(Digit::from_char(key).expect("a key"));
        let mut tone = vec![0_i16; generator.remaining()];
        generator.fill(&mut tone);
        pcm.extend(tone);
        pcm.extend(vec![0_i16; 4_000]);
        pcm
    }

    /// The fixture's far end offered no telephone event, so by default the
    /// call listens in the audio, and the key arrives as its own kind with
    /// the source that says where it was heard.
    #[test]
    fn a_digit_in_the_far_ends_audio_is_its_own_event_on_a_call_with_no_named_events() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        let media = media_of(stack, call);
        hear(stack, media, &digit('7'), 1_200);
        let heard = observed.of(SipralEventKind::InBandDigit);
        assert_eq!(heard.len(), 1, "{:?}", observed.kinds());
        let heard = &heard[0];
        assert_eq!(heard.call, call);
        assert_eq!(heard.digit, u32::from('7'));
        assert_eq!(heard.event_code, 7);
        assert!(heard.held_ms.abs_diff(100) <= 10, "{}", heard.held_ms);
        assert_eq!(heard.source, SipralDigitSource::InBand as u32);
        assert!(
            observed.of(SipralEventKind::DigitReceived).is_empty(),
            "the same press was reported as an event of RFC 4733's as well"
        );
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    /// Off is off: the same digit, and nothing reported.
    #[test]
    fn a_call_told_not_to_listen_hears_no_digit_in_the_audio() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        assert_eq!(
            unsafe { sipral_call_dtmf_detection(stack, call, SipralDtmfDetection::Off as u32) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let media = media_of(stack, call);
        hear(stack, media, &digit('4'), 1_200);
        assert!(observed.of(SipralEventKind::InBandDigit).is_empty());
        assert_eq!(
            unsafe { sipral_call_dtmf_detection(stack, call, 3) },
            SipralStatus::InvalidArgument
        );
        assert!(
            last_error_text().contains("always"),
            "{}",
            last_error_text()
        );
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    fn progress_config() -> SipralProgressConfig {
        SipralProgressConfig {
            size: size_of::<SipralProgressConfig>(),
            listen: 0,
            region: 0,
            answering_machine: 0,
            beep: 0,
            beep_window_ms: 0,
            max_initial_silence_ms: 0,
            max_greeting_ms: 0,
            silence_after_greeting_ms: 0,
            max_words: 0,
            min_word_ms: 0,
            min_word_gap_ms: 0,
            max_decision_ms: 0,
            min_speech_above_floor_db: 0,
            beep_min_ms: 0,
            beep_max_ms: 0,
            tone_cycles: 0,
        }
    }

    /// A greeting that runs on, after an answer this stack was told to
    /// listen through, is reported as a machine: the whole path, from the
    /// call's own settings before it was answered to the event's own arm.
    #[test]
    fn a_placed_call_answered_by_a_long_greeting_is_reported_as_a_machine() {
        let mut observed = Observed::default();
        let (stack, account) = media_line(&mut observed, |_| {});
        let (status, call) = place(stack, account, &managed_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        assert_eq!(
            unsafe { sipral_call_detect_progress(stack, call, &progress_config()) },
            SipralStatus::Ok,
            "{}",
            last_error_text()
        );
        let invite = one(stack);
        deliver(stack, &accepted(&invite, ANSWER, true), 1_100);
        poll(stack, 1_100);
        let _ = sent(stack);

        let mut greeting = vec![0_i16; 4_000];
        for n in 0..32_000_u32 {
            let t = f64::from(n) / 8_000.0;
            let voiced = (n / 1_600) % 2 == 0;
            let value = if voiced {
                6_000.0
                    * (2.0 * std::f64::consts::PI * 180.0 * t).sin()
                    * (1.0 + 0.5 * (2.0 * std::f64::consts::PI * 700.0 * t).sin())
            } else {
                0.0
            };
            // inside the sixteen-bit range by construction
            #[allow(clippy::cast_possible_truncation)]
            greeting.push(value.round() as i16);
        }
        greeting.extend(vec![0_i16; 8_000]);
        let media = media_of(stack, call);
        hear(stack, media, &greeting, 1_200);
        let verdicts: Vec<_> = observed
            .progress
            .iter()
            .filter(|heard| heard.0 == SipralProgressKind::AnsweredBy as u32)
            .collect();
        assert_eq!(verdicts.len(), 1, "{:?}", observed.progress);
        assert_eq!(verdicts[0].2, SipralAmdVerdict::Machine as u32);
        assert!(verdicts[0].4 > 1_000, "decided after {} ms", verdicts[0].4);
        release(media);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    #[test]
    fn a_progress_configuration_no_detector_takes_is_refused_and_changes_nothing() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        for (bad, said) in [
            (
                SipralProgressConfig {
                    region: 3,
                    ..progress_config()
                },
                "region",
            ),
            (
                SipralProgressConfig {
                    tone_cycles: 5,
                    ..progress_config()
                },
                "tone_cycles",
            ),
            (
                SipralProgressConfig {
                    beep_min_ms: 900,
                    beep_max_ms: 300,
                    ..progress_config()
                },
                "beep_min_ms",
            ),
            (
                SipralProgressConfig {
                    listen: 7,
                    ..progress_config()
                },
                "listen",
            ),
        ] {
            assert_eq!(
                unsafe { sipral_call_detect_progress(stack, call, &raw const bad) },
                SipralStatus::InvalidArgument,
                "{said}"
            );
            assert!(last_error_text().contains(said), "{}", last_error_text());
        }
        let stop = SipralProgressConfig {
            listen: 2,
            ..progress_config()
        };
        assert_eq!(
            unsafe { sipral_call_detect_progress(stack, call, &raw const stop) },
            SipralStatus::Ok
        );
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    fn tone() -> SipralConsentTone {
        SipralConsentTone {
            size: size_of::<SipralConsentTone>(),
            enabled: 0,
            frequency_hz: 0,
            attenuation_db: 0,
            length_ms: 0,
            interval_ms: 0,
            local: 0,
        }
    }

    #[test]
    fn a_consent_tone_that_is_not_a_beep_is_refused_by_member() {
        let mut observed = Observed::default();
        let (stack, call) = media_call(&mut observed);
        assert_eq!(
            unsafe { sipral_call_consent_tone(stack, call, &tone()) },
            SipralStatus::Ok,
            "the defaults are a beep"
        );
        for (bad, said) in [
            (
                SipralConsentTone {
                    frequency_hz: 5_000,
                    ..tone()
                },
                "frequency_hz",
            ),
            (
                SipralConsentTone {
                    attenuation_db: 2,
                    ..tone()
                },
                "attenuation_db",
            ),
            (
                SipralConsentTone {
                    length_ms: 10,
                    ..tone()
                },
                "length",
            ),
            (
                SipralConsentTone {
                    length_ms: 500,
                    interval_ms: 400,
                    ..tone()
                },
                "interval",
            ),
        ] {
            assert_eq!(
                unsafe { sipral_call_consent_tone(stack, call, &raw const bad) },
                SipralStatus::InvalidArgument,
                "{said}"
            );
            assert!(last_error_text().contains(said), "{}", last_error_text());
        }
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }

    /// A call whose media this stack does not describe has nothing for any of
    /// the three to reach.
    #[test]
    fn a_call_whose_media_is_not_this_stacks_is_the_wrong_state_for_all_three() {
        let mut observed = Observed::default();
        let (stack, call) = connected(&mut observed);
        assert_eq!(
            unsafe { sipral_call_dtmf_detection(stack, call, 0) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_detect_progress(stack, call, &progress_config()) },
            SipralStatus::WrongState
        );
        assert_eq!(
            unsafe { sipral_call_consent_tone(stack, call, &tone()) },
            SipralStatus::WrongState
        );
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }
}
