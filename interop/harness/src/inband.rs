// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! What a call carries inside its audio, against a real PBX, and a call
//! recorded to files a second reader then checks.
//!
//! Three flows, each only when named (`SIPRAL_FLOWS`), all straight at
//! Asterisk, all on the account `SIPRAL_USER` names — `scripts/lab.sh`
//! names Asterisk's `labuser-inband`, which has `dtmf_mode=inband` and so
//! offers and takes no telephone event at all:
//!
//! - **`inband`**: the digits this end dials therefore go out as their two
//!   tones, which Asterisk's own detector reads
//!   (`interop/asterisk/extensions.conf`'s 9030, `Read()`), and Asterisk
//!   writes them straight back with `SendDTMF()` — as tones again, on that
//!   endpoint — for this end's detector to hear. The flow passes when every
//!   digit heard came from the audio and they are the digits dialled, in
//!   order.
//! - **`amd`**: a call to 9031, which sends early media first — the ringback
//!   of Asterisk's own country, North America unless configured otherwise —
//!   then answers and plays a greeting and a machine's beep from files this
//!   binary wrote (`--write-greeting`, which `scripts/lab.sh` copies into
//!   the container before the call): a recorded greeting played by the far
//!   end. The call listens with a `ProgressDetection` for North America and
//!   has to hear the ringback on early media, a verdict of a machine after
//!   answer, and the beep.
//! - **`recording`**: a call to the echo (9008), recorded twice while it
//!   runs — stereo WAV at 16 kHz, then Ogg Opus where this binary was built
//!   with the `opus` feature — into `SIPRAL_RECORDINGS`, each file read back
//!   here: the header, the channels, the rate and a length that matches the
//!   time recorded, and for Ogg every page's checksum and an end-of-stream
//!   page. `scripts/lab.sh` then hands the files to `soxi` and `opusinfo`,
//!   readers that are not this stack's own.

use std::env;
use std::f64::consts::PI;
use std::fs::File;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use sipral::{
    AmdVerdict, CallHandle, CallMedia, CallProgress, CodecCatalog, DEFAULT_DIGIT, DigitSource,
    Event, MediaConfig, MediaEvent, OutgoingCall, ProgressDetection, ProgressTone, RecordingFormat,
    RecordingLayout, RecordingOptions, ToneRegion, UaEvent,
};

use crate::{Endpoint, place_call, run_folded, uri};

/// Each flow's own endpoint identity, folded with the run's own entropy the
/// way every other flow's is. Listed in `main.rs`'s
/// `tests::endpoint_identity_constants_are_distinct`.
pub(crate) const INBAND_SEED: u8 = 60;
pub(crate) const INBAND_MEDIA_SEED: u8 = 61;
pub(crate) const AMD_SEED: u8 = 62;
pub(crate) const AMD_MEDIA_SEED: u8 = 63;
pub(crate) const RECORDING_SEED: u8 = 64;
pub(crate) const RECORDING_MEDIA_SEED: u8 = 65;

/// `interop/asterisk/extensions.conf`'s in-band echo of digits.
const INBAND_EXTENSION: &str = "9030";

/// And its greeting, beep and all.
const MACHINE_EXTENSION: &str = "9031";

/// And its echo.
const ECHO_EXTENSION: &str = "9008";

/// What the in-band flow dials: four keys, no `#`, which `Read()` takes as
/// the end of input rather than a digit.
const DIALLED: &str = "1597";

/// How long a flow is given to come up and do what it came for.
const PATIENCE: Duration = Duration::from_secs(40);

/// How long the call is let settle before the digits go: past the far
/// end's probation and its jitter buffer's fill, so the first tone is not
/// the one that is clipped.
const SETTLE: Duration = Duration::from_secs(1);

/// How long each recording runs.
const RECORDED: Duration = Duration::from_secs(3);

/// The two files `--write-greeting` writes, as Asterisk's `Playback()`
/// names them: raw signed linear at 8 kHz, which Asterisk reads as `.sln`
/// with no header to disagree about.
const GREETING_FILE: &str = "sipral-greeting.sln";
const BEEP_FILE: &str = "sipral-beep.sln";

/// The greeting's shape: this many voiced syllables, each this long, with
/// this much silence between, after this much silence from answer — the
/// many-worded, seconds-long greeting a machine plays, which a person
/// answering does not.
const SYLLABLES: u32 = 12;
const SYLLABLE_MS: u32 = 260;
const GAP_MS: u32 = 110;
const LEAD_MS: u32 = 400;

/// The rate both files are written at, the one `.sln` means to Asterisk.
const RATE: u32 = 8_000;

/// The beep after it: one frequency, half a second.
const BEEP_HZ: f64 = 1_000.0;
const BEEP_MS: u32 = 500;

/// Write the greeting and the beep into `dir`, for `scripts/lab.sh` to hand
/// to Asterisk.
///
/// A voice rather than a tone for the greeting, because the answering-machine
/// detector counts words by a voice activity detector: a glottal-like
/// fundamental that glides through each syllable under two formants that
/// move, with an envelope that opens and closes, which is what that detector
/// reads as speech.
///
/// # Errors
/// Whatever the file system says.
pub(crate) fn write_greeting(dir: &Path) -> Result<(), String> {
    write_sln(&dir.join(GREETING_FILE), &greeting())?;
    write_sln(&dir.join(BEEP_FILE), &beep())
}

/// The greeting [`write_greeting`] writes, at 8 kHz.
fn greeting() -> Vec<i16> {
    let rate = RATE;
    let mut greeting: Vec<i16> = vec![0; samples(rate, LEAD_MS)];
    for syllable in 0..SYLLABLES {
        let length = samples(rate, SYLLABLE_MS);
        let base = 110.0 + 10.0 * f64::from(syllable % 4);
        let (first, second) = match syllable % 3 {
            0 => (700.0, 1_200.0),
            1 => (400.0, 2_000.0),
            _ => (550.0, 1_700.0),
        };
        for n in 0..length {
            let t = count(n) / f64::from(rate);
            let progress = count(n) / count(length);
            let envelope = (PI * progress).sin();
            let pitch = base * (1.0 + 0.15 * progress);
            let mut value = 0.0;
            for harmonic in 1..=20 {
                let frequency = pitch * f64::from(harmonic);
                if frequency > 3_600.0 {
                    break;
                }
                let formants =
                    resonance(frequency, first, 90.0) + resonance(frequency, second, 120.0);
                value += formants / f64::from(harmonic) * (2.0 * PI * frequency * t).sin();
            }
            greeting.push(sample(9_000.0 * envelope * value));
        }
        greeting.extend(std::iter::repeat_n(0, samples(rate, GAP_MS)));
    }
    greeting
}

/// The beep [`write_greeting`] writes, at 8 kHz.
fn beep() -> Vec<i16> {
    (0..samples(RATE, BEEP_MS))
        .map(|n| sample(10_000.0 * (2.0 * PI * BEEP_HZ * count(n) / f64::from(RATE)).sin()))
        .collect()
}

/// How strongly a formant at `centre` passes `frequency`.
fn resonance(frequency: f64, centre: f64, width: f64) -> f64 {
    let off = (frequency - centre) / width;
    1.0 / (1.0 + off * off)
}

fn samples(rate: u32, ms: u32) -> usize {
    usize::try_from(rate / 1_000 * ms).unwrap_or(0)
}

#[allow(clippy::cast_precision_loss)]
const fn count(n: usize) -> f64 {
    n as f64
}

#[allow(clippy::cast_possible_truncation)]
fn sample(value: f64) -> i16 {
    value.round().clamp(-32_768.0, 32_767.0) as i16
}

fn write_sln(path: &Path, pcm: &[i16]) -> Result<(), String> {
    let mut bytes = Vec::with_capacity(pcm.len() * 2);
    for value in pcm {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    File::create(path)
        .and_then(|mut file| file.write_all(&bytes))
        .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// `--write-greeting [dir]`: [`write_greeting`] into `dir`, the current
/// directory when none is named.
pub(crate) fn write_greeting_into(dir: Option<String>) -> ExitCode {
    let dir = PathBuf::from(dir.unwrap_or_else(|| ".".to_owned()));
    match write_greeting(&dir) {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            println!("{why}");
            ExitCode::FAILURE
        }
    }
}

/// A flow of this module, and the line it passes or fails under.
type Named = (
    &'static str,
    &'static str,
    fn(&Lab<'_>) -> Result<String, String>,
);

const FLOWS: [Named; 3] = [
    ("inband", "digits in the audio, both ways", run_inband),
    ("amd", "ringback, a machine and its beep", run_amd),
    ("recording", "a call recorded to files", run_recording),
];

/// Run each of this module's flows `wanted` names, printing each one's
/// line; how many failed.
pub(crate) fn run_named(lab: &Lab<'_>, wanted: &str) -> u32 {
    let mut failures = 0;
    for (name, what, flow) in FLOWS {
        if wanted.split(',').any(|named| named.trim() == name) {
            match flow(lab) {
                Ok(said) => println!("  pass  {what}{said}"),
                Err(why) => {
                    println!("  FAIL  {what} — {why}");
                    failures += 1;
                }
            }
        }
    }
    failures
}

/// What one of the three flows ran against.
pub(crate) struct Lab<'a> {
    pub(crate) server: &'a str,
    pub(crate) remote: SocketAddr,
    pub(crate) user: &'a str,
    pub(crate) pass: &'a str,
}

/// G.711 only, whatever `SIPRAL_CODEC` says for the other flows: the lab's
/// in-band endpoint allows mu-law alone, and a waveform codec is what an
/// in-band digit is sent over in the field.
fn catalog() -> CodecCatalog {
    // both names are codecs this build always has, so the fallback is never
    // taken; it keeps this a catalogue rather than a panic, as `main`'s does
    CodecCatalog::with_order(&["PCMU", "PCMA"]).unwrap_or_else(|_| CodecCatalog::new())
}

/// Register, place one call to `extension` under `config`, and drive it
/// until `heard` (each event on the call) or `tick` (each turn of the loop,
/// once the call's media session exists) says the flow has what it came
/// for, the call ends, or [`PATIENCE`] runs out. Hangs up and unregisters
/// either way.
fn call<T>(
    lab: &Lab<'_>,
    seeds: (u8, u8),
    extension: &str,
    config: &MediaConfig,
    mut heard: impl FnMut(&Event) -> Option<T>,
    mut tick: impl FnMut(&mut sipral::MediaSession, Instant) -> Option<T>,
) -> Result<T, String> {
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(
        run_folded([seeds.0; 32]),
        run_folded([seeds.1; 32]),
        SocketAddr::new(crate::route_to(lab.remote), 0),
        catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind: {error}"))?;
    let account = endpoint.account(lab.user, lab.pass, lab.server, lab.remote)?;
    let target = uri(&format!("sip:{extension}@{}", lab.server))?;
    let _ = endpoint.agent.register(account, now);
    let began = Instant::now();
    let mut registered = false;
    let mut placed: Option<CallHandle> = None;
    let mut ended = false;
    let outcome = 'run: loop {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            match &event {
                Event::Signalling(UaEvent::Registered { .. }) => registered = true,
                Event::Signalling(UaEvent::CallEnded { .. }) => ended = true,
                _ => {}
            }
            if placed.is_some()
                && let Some(done) = heard(&event)
            {
                break 'run Ok(done);
            }
        }
        if registered && placed.is_none() {
            let media = CallMedia::new(catalog(), config.clone());
            let outgoing =
                OutgoingCall::new(target.clone()).to_address(endpoint.transport, lab.remote);
            match place_call(&mut endpoint, account, outgoing, media, lab.remote, now) {
                Ok(handle) => placed = Some(handle),
                Err(why) => break Err(format!("not placed: {why}")),
            }
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        if let Some(handle) = placed
            && let Some(mut session) = endpoint.engine.session(handle)
            && let Some(done) = tick(&mut session, now)
        {
            break Ok(done);
        }
        if ended || now > began + PATIENCE {
            break Err(if ended {
                "the call ended before the flow had what it came for".to_owned()
            } else if registered {
                "the flow ran out of time".to_owned()
            } else {
                "never registered".to_owned()
            });
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    };
    if let Some(call) = placed {
        let _ = endpoint.agent.hangup(call, Instant::now());
        endpoint.flush();
    }
    let _ = endpoint.agent.unregister(account, Instant::now());
    endpoint.flush();
    outcome
}

/// `inband`: see the module documentation.
///
/// # Errors
/// What was heard instead of the digits dialled, or why nothing was.
pub(crate) fn run_inband(lab: &Lab<'_>) -> Result<String, String> {
    let mut up_at: Option<Instant> = None;
    let mut dialled = false;
    let mut heard = String::new();
    let said = call(
        lab,
        (INBAND_SEED, INBAND_MEDIA_SEED),
        INBAND_EXTENSION,
        &MediaConfig::default(),
        |event| {
            if let Event::Media {
                event:
                    MediaEvent::DigitReceived {
                        digit: Some(key),
                        source,
                        ..
                    },
                ..
            } = event
            {
                if *source != DigitSource::InBand {
                    return Some(Err(format!(
                        "{key} arrived as {source:?}, not in the audio"
                    )));
                }
                heard.push(*key);
                if heard.len() == DIALLED.len() {
                    return Some(Ok(heard.clone()));
                }
            }
            None
        },
        |session, now| {
            // dialled once, `SETTLE` after the session is first seen: with no
            // telephone event on this endpoint, `dial` puts the keys in the
            // audio, and Asterisk, which reads only the audio here, is what
            // says whether they were there
            let at = *up_at.get_or_insert(now);
            if !dialled && now >= at + SETTLE {
                dialled = true;
                if let Err(why) = session.dial(DIALLED, DEFAULT_DIGIT) {
                    return Some(Err(format!("not dialled: {why}")));
                }
            }
            None
        },
    )??;
    if said != DIALLED {
        return Err(format!("dialled {DIALLED} and heard {said}"));
    }
    Ok(format!(
        "   ({DIALLED} dialled in the audio, read there by Asterisk, and heard back in the audio)"
    ))
}

/// `amd`: see the module documentation.
///
/// # Errors
/// What was heard, when it was not ringback, a machine and a beep.
pub(crate) fn run_amd(lab: &Lab<'_>) -> Result<String, String> {
    let detection = ProgressDetection {
        region: ToneRegion::NorthAmerica,
        ..ProgressDetection::default()
    };
    let config = MediaConfig {
        progress: Some(detection),
        ..MediaConfig::default()
    };
    let mut ringback = None;
    let mut verdict = None;
    let said = call(
        lab,
        (AMD_SEED, AMD_MEDIA_SEED),
        MACHINE_EXTENSION,
        &config,
        |event| {
            let Event::Media {
                event: MediaEvent::Progress(progress),
                ..
            } = event
            else {
                return None;
            };
            match *progress {
                CallProgress::Tone {
                    tone: ProgressTone::Ringback,
                    at,
                } => ringback = Some(at),
                CallProgress::AnsweredBy {
                    verdict: said,
                    reason,
                    after,
                    words,
                    ..
                } => {
                    if said != AmdVerdict::Machine {
                        return Some(Err(format!(
                            "the greeting was taken for {said:?} ({reason:?}, {words} words)"
                        )));
                    }
                    verdict = Some((reason, after, words));
                }
                CallProgress::Beep {
                    frequency_hz,
                    ended,
                    length,
                } => {
                    return Some(Ok((frequency_hz, ended, length)));
                }
                _ => {}
            }
            None
        },
        |_, _| None,
    )??;
    let at = ringback.ok_or("no ringback was heard on the early media")?;
    let (reason, after, words) = verdict.ok_or("the beep came with no verdict before it")?;
    let (frequency, ended, length) = said;
    if (frequency - BEEP_HZ).abs() > 30.0 {
        return Err(format!("the beep was heard at {frequency:.0} Hz"));
    }
    Ok(format!(
        "   (ringback at {} ms of early media; a machine after {} ms, {reason:?}, {words} words; \
         the beep at {frequency:.0} Hz for {} ms, ended {} ms after answer)",
        at.as_millis(),
        after.as_millis(),
        length.as_millis(),
        ended.as_millis()
    ))
}

/// `recording`: see the module documentation.
///
/// # Errors
/// What a file failed, or why none was written.
pub(crate) fn run_recording(lab: &Lab<'_>) -> Result<String, String> {
    let dir = PathBuf::from(env::var("SIPRAL_RECORDINGS").unwrap_or_else(|_| "/tmp".to_owned()));
    let wav = dir.join("sipral-call.wav");
    let ogg = dir.join("sipral-call.opus");
    let mut plan: Vec<(RecordingOptions, PathBuf)> = vec![(
        RecordingOptions {
            layout: RecordingLayout::Stereo,
            sample_rate: Some(16_000),
            ..RecordingOptions::default()
        },
        wav.clone(),
    )];
    if let Some(format) = RecordingFormat::ogg_opus() {
        plan.push((
            RecordingOptions {
                format,
                layout: RecordingLayout::Stereo,
                ..RecordingOptions::default()
            },
            ogg.clone(),
        ));
    }
    let mut remaining = plan.iter();
    let mut up_at: Option<Instant> = None;
    let mut recording_since: Option<Instant> = None;
    call(
        lab,
        (RECORDING_SEED, RECORDING_MEDIA_SEED),
        ECHO_EXTENSION,
        &MediaConfig::default(),
        |event| match event {
            Event::Media {
                event: MediaEvent::RecordingStopped { reason, .. },
                ..
            } => Some(Err(format!("a recording stopped by itself: {reason}"))),
            _ => None,
        },
        |session, now| {
            let at = *up_at.get_or_insert(now);
            if now < at + SETTLE {
                return None;
            }
            match recording_since {
                None => {
                    // one after the other on the same call, which is also
                    // what shows the recorder is there to be started again
                    let Some((options, path)) = remaining.next() else {
                        return Some(Ok(()));
                    };
                    let started = File::create(path)
                        .map_err(|why| format!("{}: {why}", path.display()))
                        .and_then(|file| {
                            session
                                .start_recording_with(Box::new(file), options)
                                .map_err(|why| format!("not started: {why}"))
                        });
                    if let Err(why) = started {
                        return Some(Err(why));
                    }
                    recording_since = Some(now);
                    None
                }
                Some(since) if now >= since + RECORDED => {
                    recording_since = None;
                    if let Err(why) = session.stop_recording() {
                        return Some(Err(format!("not finished: {why}")));
                    }
                    None
                }
                Some(_) => None,
            }
        },
    )??;
    let mut said = check_wav(&wav)?;
    if plan.len() > 1 {
        said.push_str("; ");
        said.push_str(&check_ogg(&ogg)?);
    } else {
        said.push_str("; no Ogg Opus, this binary was built without Opus");
    }
    Ok(format!("   ({said})"))
}

/// A WAVE file read back: RIFF, two channels at 16 kHz, a data length the
/// header states and the file holds, and about as much audio as was
/// recorded.
fn check_wav(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|why| format!("{}: {why}", path.display()))?;
    let field = |at: usize, len: usize| -> u32 {
        bytes.get(at..at + len).map_or(0, |part| {
            part.iter()
                .rev()
                .fold(0, |value, byte| value << 8 | u32::from(*byte))
        })
    };
    if bytes.get(..4) != Some(b"RIFF") || bytes.get(8..12) != Some(b"WAVE") {
        return Err("the WAV file is not RIFF/WAVE".to_owned());
    }
    let (channels, rate, data) = (field(58, 2), field(60, 4), field(76, 4));
    if channels != 2 || rate != 16_000 {
        return Err(format!("the WAV file is {channels} channels at {rate} Hz"));
    }
    let held = bytes.len().saturating_sub(80);
    if usize::try_from(data).unwrap_or(0) != held {
        return Err(format!(
            "the header says {data} octets and the file holds {held}"
        ));
    }
    let seconds = f64::from(data) / 4.0 / 16_000.0;
    if (seconds - RECORDED.as_secs_f64()).abs() > 0.3 {
        return Err(format!(
            "{seconds:.2} s of WAV for {} s recorded",
            RECORDED.as_secs()
        ));
    }
    Ok(format!("stereo WAV at 16 kHz, {seconds:.2} s"))
}

/// An Ogg Opus stream read back: every page's checksum and sequence, an
/// `OpusHead` for two channels, and an end-of-stream page whose granule
/// position is the audio recorded after the pre-skip.
fn check_ogg(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|why| format!("{}: {why}", path.display()))?;
    let packets = sipral_media::formats::ogg::read_packets(&bytes)
        .map_err(|why| format!("the Ogg stream does not read back: {why}"))?;
    let head = packets.first().ok_or("an Ogg stream with no packets")?;
    if head.data.get(..8) != Some(b"OpusHead") || head.data.get(9) != Some(&2) {
        return Err("the first packet is not a stereo OpusHead".to_owned());
    }
    let pre_skip = u64::from(u16::from_le_bytes([
        head.data.get(10).copied().unwrap_or(0),
        head.data.get(11).copied().unwrap_or(0),
    ]));
    let last = packets.last().ok_or("an Ogg stream with no packets")?;
    if !last.eos {
        return Err("the Ogg stream has no end-of-stream page".to_owned());
    }
    let granule = last.granule.unwrap_or(0).saturating_sub(pre_skip);
    #[allow(clippy::cast_precision_loss)]
    let seconds = granule as f64 / 48_000.0;
    if (seconds - RECORDED.as_secs_f64()).abs() > 0.3 {
        return Err(format!(
            "{seconds:.2} s of Ogg Opus for {} s recorded",
            RECORDED.as_secs()
        ));
    }
    Ok(format!(
        "stereo Ogg Opus, {} packets, pre-skip {pre_skip}, {seconds:.2} s",
        packets.len().saturating_sub(2)
    ))
}

#[cfg(test)]
mod tests {
    use sipral_media::inband::SampleRate;
    use sipral_media::inband::amd::{AnsweringMachineDetector, Verdict};
    use sipral_media::inband::beep::BeepDetector;

    use super::{BEEP_HZ, beep, greeting};

    /// Twenty milliseconds at 8 kHz, the frame the call hands its detectors.
    const FRAME: usize = 160;

    #[test]
    fn the_greeting_written_for_the_lab_is_one_the_detector_calls_a_machine() {
        // and says so while the greeting is still playing: the beep follows
        // it, and a machine's beep is listened for only once the verdict is in
        let mut detector = AnsweringMachineDetector::new(SampleRate::Hz8000);
        let greeting = greeting();
        let result = greeting
            .chunks(FRAME)
            .find_map(|frame| detector.process(frame))
            .expect("a verdict before the greeting ends");
        assert_eq!(result.verdict, Verdict::Machine, "{result:?}");
    }

    #[test]
    fn the_beep_written_for_the_lab_is_heard_once_and_the_greeting_before_it_never() {
        let mut detector = BeepDetector::new(SampleRate::Hz8000);
        let mut heard = greeting();
        heard.extend(beep());
        heard.extend(std::iter::repeat_n(0, 8_000));
        let mut beeps = Vec::new();
        for frame in heard.chunks(FRAME) {
            detector.process(frame, |found| beeps.push(found.frequency_hz));
        }
        assert_eq!(beeps.len(), 1, "{beeps:?}");
        assert!(
            beeps.iter().all(|hz| (hz - BEEP_HZ).abs() < 30.0),
            "{beeps:?}"
        );
    }
}
