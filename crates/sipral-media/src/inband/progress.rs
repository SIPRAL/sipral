// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Call-progress tones: what a network plays to a caller while it connects
//! a call, or instead of connecting it.
//!
//! The tones are data, not code. A [`ToneSpec`] names a tone, its
//! frequencies, and its cadence — a repeating list of [`Burst`]s of tone and
//! silence, or [`Cadence::Continuous`] — and a [`Region`] is a table of
//! them. The same table drives [`ToneGenerator`](super::generate::ToneGenerator)
//! and [`ProgressDetector`], so a tone generated here is, by construction,
//! the tone detected here.
//!
//! # Where the tables come from
//!
//! ITU-T E.180 recommends the characteristics of these tones, and its
//! Supplement 2, *Various tones used in national networks*, lists what each
//! administration actually plays. The three tables here are taken from it:
//!
//! - [`Region::Europe`]: the 425 Hz tones common to the CEPT
//!   administrations, which follow E.180's recommended frequency and
//!   ETSI's harmonised cadences: dial continuous, ringing 1 s on and 4 s
//!   off, busy 0.5 s on and off, congestion 0.25 s on and off, and call
//!   waiting as two 0.2 s bursts.
//! - [`Region::NorthAmerica`]: the precise tone plan the United States and
//!   Canada entries list: dial 350 + 440 Hz, audible ringing 440 + 480 Hz at
//!   2 s on and 4 s off, busy 480 + 620 Hz at 0.5 s, reorder at 0.25 s, and
//!   call waiting a single 0.3 s burst of 440 Hz.
//! - [`Region::UnitedKingdom`]: the United Kingdom entry: dial 350 + 440 Hz,
//!   ringing 400 + 450 Hz in the double ring of 0.4 s on, 0.2 s off, 0.4 s on
//!   and 2 s off, busy 400 Hz at 0.375 s, congestion (equipment engaged)
//!   400 Hz at 0.4 s on, 0.35 s off, 0.225 s on and 0.525 s off, and call
//!   waiting a 0.1 s burst of 400 Hz.
//!
//! Where an administration's entry lists a range or several variants, the
//! value here is the one most of that region's networks play. A network
//! with a tone of its own is a [`ToneSpec`] away: the fields are public and
//! the detector takes any slice of them.
//!
//! # The special information tone
//!
//! E.180 defines one tone every network plays alike: three frequencies,
//! [`SIT_FREQUENCIES`], each for [`SIT_DURATION_MS`], in rising order, then
//! [`SIT_SILENCE_MS`] of silence, to say that a call failed for a reason an
//! announcement usually follows with. E.180 allows each frequency ±50 Hz,
//! each tone 330 ± 70 ms, and up to 30 ms of silence between the tones.
//! North American networks send the same three tones slightly moved and
//! lengthened or shortened to say which reason; every one of those
//! variants falls inside E.180's tolerances, and [`ProgressEvent`] carries
//! the frequencies and durations it measured for a caller that wants to
//! tell them apart.

use std::collections::VecDeque;

use super::analysis::{Analyzer, Claim, Hop, HopTracker, end_edge, start_edge};
use super::{SampleRate, count_f64, dbm0_to_power, position_f64, round_position};

/// What a call-progress tone means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProgressTone {
    /// The exchange is ready for digits.
    Dial,
    /// The far end is being alerted: audible ringing, or ringback.
    Ringback,
    /// The far end is busy.
    Busy,
    /// The network is congested: congestion, or reorder in North America.
    Congestion,
    /// A second call is waiting, played over the first.
    CallWaiting,
    /// E.180's special information tone: the call failed and the network
    /// has something to say about why.
    SpecialInformation,
}

/// One burst of a cadence: tone for `on_ms`, then silence for `off_ms`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Burst {
    /// How long the tone sounds, in milliseconds.
    pub on_ms: u32,
    /// How long the silence after it lasts, in milliseconds.
    pub off_ms: u32,
}

/// How a tone is switched on and off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cadence {
    /// Never off.
    Continuous,
    /// These bursts, in order, over and over.
    Repeating(&'static [Burst]),
}

/// One call-progress tone of one network.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ToneSpec {
    /// What it means.
    pub tone: ProgressTone,
    /// The frequencies that sound together, in hertz.
    pub frequencies: &'static [f64],
    /// How they are switched.
    pub cadence: Cadence,
}

/// A network whose tones are tabled here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Region {
    /// The 425 Hz tones common to the CEPT administrations.
    Europe,
    /// The United States and Canada.
    NorthAmerica,
    /// The United Kingdom.
    UnitedKingdom,
}

impl Region {
    /// Every region tabled.
    pub const ALL: [Self; 3] = [Self::Europe, Self::NorthAmerica, Self::UnitedKingdom];

    /// The region's tones.
    #[must_use]
    pub const fn tones(self) -> &'static [ToneSpec] {
        match self {
            Self::Europe => &EUROPE,
            Self::NorthAmerica => &NORTH_AMERICA,
            Self::UnitedKingdom => &UNITED_KINGDOM,
        }
    }
}

const fn burst(on_ms: u32, off_ms: u32) -> Burst {
    Burst { on_ms, off_ms }
}

/// The CEPT common tones, E.180 Supplement 2.
pub const EUROPE: [ToneSpec; 5] = [
    ToneSpec {
        tone: ProgressTone::Dial,
        frequencies: &[425.0],
        cadence: Cadence::Continuous,
    },
    ToneSpec {
        tone: ProgressTone::Ringback,
        frequencies: &[425.0],
        cadence: Cadence::Repeating(&[burst(1_000, 4_000)]),
    },
    ToneSpec {
        tone: ProgressTone::Busy,
        frequencies: &[425.0],
        cadence: Cadence::Repeating(&[burst(500, 500)]),
    },
    ToneSpec {
        tone: ProgressTone::Congestion,
        frequencies: &[425.0],
        cadence: Cadence::Repeating(&[burst(250, 250)]),
    },
    ToneSpec {
        tone: ProgressTone::CallWaiting,
        frequencies: &[425.0],
        cadence: Cadence::Repeating(&[burst(200, 200), burst(200, 4_400)]),
    },
];

/// The United States and Canada, E.180 Supplement 2.
pub const NORTH_AMERICA: [ToneSpec; 5] = [
    ToneSpec {
        tone: ProgressTone::Dial,
        frequencies: &[350.0, 440.0],
        cadence: Cadence::Continuous,
    },
    ToneSpec {
        tone: ProgressTone::Ringback,
        frequencies: &[440.0, 480.0],
        cadence: Cadence::Repeating(&[burst(2_000, 4_000)]),
    },
    ToneSpec {
        tone: ProgressTone::Busy,
        frequencies: &[480.0, 620.0],
        cadence: Cadence::Repeating(&[burst(500, 500)]),
    },
    ToneSpec {
        tone: ProgressTone::Congestion,
        frequencies: &[480.0, 620.0],
        cadence: Cadence::Repeating(&[burst(250, 250)]),
    },
    ToneSpec {
        tone: ProgressTone::CallWaiting,
        frequencies: &[440.0],
        cadence: Cadence::Repeating(&[burst(300, 9_700)]),
    },
];

/// The United Kingdom, E.180 Supplement 2.
pub const UNITED_KINGDOM: [ToneSpec; 5] = [
    ToneSpec {
        tone: ProgressTone::Dial,
        frequencies: &[350.0, 440.0],
        cadence: Cadence::Continuous,
    },
    ToneSpec {
        tone: ProgressTone::Ringback,
        frequencies: &[400.0, 450.0],
        cadence: Cadence::Repeating(&[burst(400, 200), burst(400, 2_000)]),
    },
    ToneSpec {
        tone: ProgressTone::Busy,
        frequencies: &[400.0],
        cadence: Cadence::Repeating(&[burst(375, 375)]),
    },
    ToneSpec {
        tone: ProgressTone::Congestion,
        frequencies: &[400.0],
        cadence: Cadence::Repeating(&[burst(400, 350), burst(225, 525)]),
    },
    ToneSpec {
        tone: ProgressTone::CallWaiting,
        frequencies: &[400.0],
        cadence: Cadence::Repeating(&[burst(100, 2_000)]),
    },
];

/// The special information tone's three frequencies, in the order they
/// sound, in hertz (E.180).
pub const SIT_FREQUENCIES: [f64; 3] = [950.0, 1_400.0, 1_800.0];

/// How long each of the three sounds, in milliseconds (E.180: 330 ± 70).
pub const SIT_DURATION_MS: [u32; 3] = [330, 330, 330];

/// The silence after the three, before they repeat, in milliseconds
/// (E.180: 1 s ± 250 ms).
pub const SIT_SILENCE_MS: u32 = 1_000;

/// The ceiling on [`ProgressConfig::cycles`].
const MAX_CYCLES: u32 = 4;

/// Bursts and silences remembered per set of frequencies: four cycles of a
/// two-burst cadence and one burst more, rounded up to keep the history
/// starting with a burst when the oldest pair is dropped.
const HISTORY: usize = 18;

/// The limits of a [`ProgressDetector`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProgressConfig {
    /// The least level, in dBm0, a tone's frequencies may have together.
    /// Default −38 dBm0, a judgement: well under the level a network plays
    /// these tones at, even after a long connection's loss, and well over
    /// the idle noise of a line.
    pub min_level_dbm0: f64,
    /// How far a tone's frequencies together must stand above everything
    /// else in the window, in dB. Default 6 dB, a judgement, which a steady
    /// tone clears easily and a voice rarely does.
    pub min_signal_to_noise_db: f64,
    /// How much weaker than the strongest of a tone's frequencies any other
    /// of them may be, in dB. Default 10 dB, a judgement: a network sends
    /// them at one level, and a tone with one of its pair missing is
    /// another tone.
    pub max_imbalance_db: f64,
    /// How far a burst or a silence may be from its nominal length, as a
    /// fraction of it. Default 0.2, a judgement: wide enough for a
    /// network's own drift and the measurement's error, narrow enough that
    /// busy and congestion, 500 and 250 ms, stay apart.
    pub cadence_tolerance: f64,
    /// The same, as a floor in milliseconds, for the short bursts where a
    /// fraction is less than the measurement's own error. Default 40, a
    /// judgement.
    pub cadence_slack_ms: u32,
    /// How long a tone with a continuous cadence has to sound before it is
    /// reported, in milliseconds. Default 2500, longer than any burst of a
    /// repeating cadence tabled here plus its tolerance, so that ringing's
    /// two-second burst is not taken for a dial tone.
    pub continuous_ms: u32,
    /// How many whole cycles of a repeating cadence have to be heard before
    /// it is reported, from one to four. Default 1.
    pub cycles: u32,
    /// The widest a special information tone may be from each of its three
    /// nominal frequencies, in hertz. Default 50, E.180's tolerance.
    pub sit_tolerance_hz: f64,
    /// The shortest and longest each of the three may sound, in
    /// milliseconds. Default 250 and 410: E.180's 330 ± 70 ms, with 10 ms
    /// either side for the measurement.
    pub sit_duration_ms: (u32, u32),
    /// The longest silence between two of the three, in milliseconds.
    /// Default 40: E.180's 30, and 10 for the measurement.
    pub sit_max_gap_ms: u32,
}

impl Default for ProgressConfig {
    fn default() -> Self {
        Self {
            min_level_dbm0: -38.0,
            min_signal_to_noise_db: 6.0,
            max_imbalance_db: 10.0,
            cadence_tolerance: 0.2,
            cadence_slack_ms: 40,
            continuous_ms: 2_500,
            cycles: 1,
            sit_tolerance_hz: 50.0,
            sit_duration_ms: (250, 410),
            sit_max_gap_ms: 40,
        }
    }
}

/// What the special information tone sounded like, for a caller that tells
/// the North American variants apart.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SitMeasurement {
    /// The frequency of each of the three, in hertz, as measured.
    pub frequencies: [f64; 3],
    /// How long each sounded, in milliseconds, as measured.
    pub durations_ms: [u32; 3],
}

/// A call-progress tone heard.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProgressEvent {
    /// What it means.
    pub tone: ProgressTone,
    /// Which of the detector's specs matched, as an index into the slice it
    /// was built with; `None` for the special information tone, which is
    /// not one of them.
    pub spec: Option<usize>,
    /// The first sample of the first burst of the pattern that matched.
    pub start: u64,
    /// For the special information tone, what was measured.
    pub sit: Option<SitMeasurement>,
}

const WINDOW_MS: u32 = 50;
const HOP_MS: u32 = 10;
const SIT_WINDOW_MS: u32 = 20;
const SIT_HOP_MS: u32 = 5;

/// The gap inside a burst, in milliseconds, that is taken for a dropout —
/// a lost packet concealed badly — rather than the end of the burst.
/// Shorter than any silence in any cadence tabled.
const BRIDGE_MS: f64 = 40.0;

/// A set of frequencies that some spec sounds together, as indices into
/// the filter bank.
#[derive(Clone, Debug)]
struct Signature {
    bins: Vec<usize>,
}

/// A stretch of one signature sounding, or of it not sounding.
#[derive(Clone, Copy, Debug)]
struct Span {
    start: f64,
    length: f64,
}

/// What one signature has done lately.
#[derive(Clone, Debug)]
struct History {
    /// Alternating burst and silence, oldest first, always starting with a
    /// burst.
    spans: VecDeque<Span>,
    last_end: Option<f64>,
}

/// A signature being heard.
#[derive(Clone, Copy, Debug)]
struct Run {
    signature: usize,
    start: f64,
    end: f64,
    last_on: u64,
    last_coverage: f64,
    last_claim: f64,
    continuous_reported: bool,
}

/// Where the special information tone's sequence has got to.
#[derive(Clone, Copy, Debug, Default)]
struct SitProgress {
    /// Tones of the three heard so far, in order.
    heard: usize,
    start: f64,
    last_end: f64,
    durations: [f64; 3],
}

/// A run of one of the special information tone's three frequencies.
#[derive(Clone, Copy, Debug)]
struct SitRun {
    band: usize,
    start: f64,
    end: f64,
    last_on: u64,
    last_coverage: f64,
    last_claim: f64,
}

/// Detects call-progress tones, and the special information tone, on one
/// stream of a call's inbound audio.
#[derive(Clone, Debug)]
pub struct ProgressDetector {
    config: ProgressConfig,
    specs: &'static [ToneSpec],
    spec_signature: Vec<usize>,
    reported: Vec<bool>,
    signatures: Vec<Signature>,
    histories: Vec<History>,
    bank: Analyzer,
    hops: HopTracker<usize>,
    hop_len: f64,
    per_ms: f64,
    min_power: f64,
    signal_to_noise: f64,
    imbalance: f64,
    previous: Option<Hop<usize>>,
    run: Option<Run>,
    sit_bank: Analyzer,
    sit_hops: HopTracker<usize>,
    sit_hop_len: f64,
    sit_previous: Option<Hop<usize>>,
    sit_run: Option<SitRun>,
    sit: SitProgress,
    sit_offsets: [(f64, f64); 3],
}

impl ProgressDetector {
    /// A detector for `specs` — one [`Region`]'s tones, or any other set —
    /// at `rate`, with the default limits.
    #[must_use]
    pub fn new(rate: SampleRate, specs: &'static [ToneSpec]) -> Self {
        Self::with_config(rate, specs, ProgressConfig::default())
    }

    /// A detector with explicit limits.
    #[must_use]
    pub fn with_config(
        rate: SampleRate,
        specs: &'static [ToneSpec],
        config: ProgressConfig,
    ) -> Self {
        let mut frequencies: Vec<f64> = Vec::new();
        let mut signatures: Vec<Signature> = Vec::new();
        let mut spec_signature = Vec::with_capacity(specs.len());
        for spec in specs {
            let mut bins: Vec<usize> = spec
                .frequencies
                .iter()
                .map(|&f| {
                    frequencies
                        .iter()
                        .position(|&known| (known - f).abs() < 0.5)
                        .unwrap_or_else(|| {
                            frequencies.push(f);
                            frequencies.len() - 1
                        })
                })
                .collect();
            bins.sort_unstable();
            bins.dedup();
            let index = signatures
                .iter()
                .position(|s| s.bins == bins)
                .unwrap_or_else(|| {
                    signatures.push(Signature { bins });
                    signatures.len() - 1
                });
            spec_signature.push(index);
        }
        let bank = Analyzer::new(rate, WINDOW_MS, HOP_MS, &frequencies);
        let hops = HopTracker::new(bank.hops_per_window());
        let hop_len = count_f64(bank.hop());
        let sit_bank = Analyzer::new(rate, SIT_WINDOW_MS, SIT_HOP_MS, &SIT_FREQUENCIES);
        let sit_hops = HopTracker::new(sit_bank.hops_per_window());
        let sit_hop_len = count_f64(sit_bank.hop());
        // one at a time: `vec![history; n]` would clone it, and a clone of a
        // `VecDeque` does not keep the capacity reserved for it
        let histories = signatures
            .iter()
            .map(|_| History {
                spans: VecDeque::with_capacity(HISTORY + 1),
                last_end: None,
            })
            .collect();
        let config = ProgressConfig {
            cycles: config.cycles.clamp(1, MAX_CYCLES),
            ..config
        };
        Self {
            min_power: dbm0_to_power(config.min_level_dbm0),
            signal_to_noise: 10f64.powf(config.min_signal_to_noise_db / 10.0),
            imbalance: 10f64.powf(config.max_imbalance_db / 10.0),
            per_ms: rate.as_f64() / 1_000.0,
            config,
            specs,
            reported: vec![false; specs.len()],
            spec_signature,
            signatures,
            histories,
            bank,
            hops,
            hop_len,
            previous: None,
            run: None,
            sit_bank,
            sit_hops,
            sit_hop_len,
            sit_previous: None,
            sit_run: None,
            sit: SitProgress::default(),
            sit_offsets: [(0.0, 0.0); 3],
        }
    }

    /// The specs the detector was built with.
    #[must_use]
    pub const fn specs(&self) -> &'static [ToneSpec] {
        self.specs
    }

    /// The limits the detector was built with, with `cycles` held to its
    /// range.
    #[must_use]
    pub const fn config(&self) -> &ProgressConfig {
        &self.config
    }

    /// Forget the stream: the next sample is sample zero of a new one.
    pub fn reset(&mut self) {
        self.bank.reset();
        self.hops.reset();
        self.previous = None;
        self.run = None;
        for history in &mut self.histories {
            history.spans.clear();
            history.last_end = None;
        }
        for reported in &mut self.reported {
            *reported = false;
        }
        self.sit_bank.reset();
        self.sit_hops.reset();
        self.sit_previous = None;
        self.sit_run = None;
        self.sit = SitProgress::default();
        self.sit_offsets = [(0.0, 0.0); 3];
    }

    /// Listen to `samples`, the next ones of the stream, and report every
    /// tone they complete.
    pub fn process(&mut self, samples: &[i16], mut on_event: impl FnMut(ProgressEvent)) {
        for &sample in samples {
            if self.bank.push(sample) {
                let claim = self.classify();
                let hop = self
                    .hops
                    .push(self.bank.hop_index(), self.bank.hop_power(), claim);
                if let Some(hop) = hop {
                    self.on_hop(hop, &mut on_event);
                }
            }
            if self.sit_bank.push(sample) {
                let claim = self.classify_sit();
                let hop =
                    self.sit_hops
                        .push(self.sit_bank.hop_index(), self.sit_bank.hop_power(), claim);
                if let Some(hop) = hop {
                    self.on_sit_hop(hop, &mut on_event);
                }
            }
        }
    }

    /// Which signature, if any, the last window holds.
    fn classify(&mut self) -> Option<Claim<usize>> {
        let bank = self.bank.window();
        let total = bank.total_power();
        let power_at = |bin: usize| {
            bank.reading(bin).map_or(0.0, |r| {
                let amplitude = bank.amplitude_at_centre(r.magnitude);
                amplitude * amplitude / 2.0
            })
        };
        self.signatures
            .iter()
            .enumerate()
            .filter_map(|(index, signature)| {
                let powers = signature.bins.iter().map(|&b| power_at(b));
                let tone: f64 = powers.clone().sum();
                let strongest = powers.clone().fold(0.0, f64::max);
                let weakest = powers.fold(f64::INFINITY, f64::min);
                let passes = tone >= self.min_power
                    && tone >= self.signal_to_noise * (total - tone).max(0.0)
                    && weakest * self.imbalance >= strongest;
                passes.then_some(Claim {
                    class: index,
                    power: tone,
                })
            })
            .max_by(|a, b| a.power.total_cmp(&b.power))
    }

    fn on_hop(&mut self, hop: Hop<usize>, on_event: &mut impl FnMut(ProgressEvent)) {
        let before = self.previous.replace(hop);
        let h = self.hop_len;
        let bridge = BRIDGE_MS * self.per_ms;
        let hop_start = position_f64(hop.index) * h;
        if let (Some(signature), Some(claim)) = (hop.on(), hop.claim) {
            let coverage = hop.coverage(claim.power);
            let before_coverage = before
                .filter(|b| b.on().is_none())
                .map_or(0.0, |b| b.coverage(claim.power));
            let start = start_edge(hop_start, h, coverage, before_coverage);
            let end = end_edge(hop_start + h, h, coverage, 0.0);
            let continues = self.run.is_some_and(|run| {
                run.signature == signature
                    && (run.last_on + 1 == hop.index || start - run.end < bridge)
            });
            if continues {
                if let Some(run) = self.run.as_mut() {
                    run.end = end;
                    run.last_on = hop.index;
                    run.last_coverage = coverage;
                    run.last_claim = claim.power;
                }
            } else {
                if let Some(run) = self.run.take() {
                    self.close_run(run, on_event);
                }
                self.open_run(signature, start);
                self.run = Some(Run {
                    signature,
                    start,
                    end,
                    last_on: hop.index,
                    last_coverage: coverage,
                    last_claim: claim.power,
                    continuous_reported: false,
                });
            }
        } else if let Some(run) = self.run.as_mut() {
            if run.last_on + 1 == hop.index {
                let after = hop.coverage(run.last_claim);
                run.end = end_edge(hop_start, h, run.last_coverage, after);
            }
            if hop_start + 0.5 * h - run.end >= bridge
                && let Some(run) = self.run.take()
            {
                self.close_run(run, on_event);
            }
        }
        self.check_continuous(on_event);
    }

    /// A burst of `signature` has begun at `start`: the silence before it
    /// is now known.
    fn open_run(&mut self, signature: usize, start: f64) {
        if let Some(history) = self.histories.get_mut(signature)
            && let Some(last_end) = history.last_end
        {
            push_span(
                &mut history.spans,
                Span {
                    start: last_end,
                    length: start - last_end,
                },
            );
        }
    }

    /// A burst has ended, and with it perhaps a cadence.
    ///
    /// Matching waits for a burst's end rather than a silence's, so every
    /// cadence is heard one burst past its whole cycle. Without that, the
    /// first burst and silence of the United Kingdom's congestion tone, 400
    /// and 350 ms, would pass for a cycle of its busy tone, 375 and 375.
    fn close_run(&mut self, run: Run, on_event: &mut impl FnMut(ProgressEvent)) {
        let Some(history) = self.histories.get_mut(run.signature) else {
            return;
        };
        push_span(
            &mut history.spans,
            Span {
                start: run.start,
                length: run.end - run.start,
            },
        );
        history.last_end = Some(run.end);
        for (index, spec) in self.specs.iter().enumerate() {
            if self.spec_signature.get(index) != Some(&run.signature) {
                continue;
            }
            let Cadence::Repeating(bursts) = spec.cadence else {
                continue;
            };
            let matched = matches_cadence(&history.spans, bursts, &self.config, self.per_ms);
            let Some(reported) = self.reported.get_mut(index) else {
                continue;
            };
            match matched {
                Some(first) if !*reported => {
                    *reported = true;
                    on_event(ProgressEvent {
                        tone: spec.tone,
                        spec: Some(index),
                        start: round_position(first),
                        sit: None,
                    });
                }
                Some(_) => {}
                None => *reported = false,
            }
        }
    }

    /// Report a continuous tone once it has sounded long enough.
    fn check_continuous(&mut self, on_event: &mut impl FnMut(ProgressEvent)) {
        let needed = f64::from(self.config.continuous_ms) * self.per_ms;
        let Some(run) = self.run.as_mut() else {
            return;
        };
        if run.continuous_reported || run.end - run.start < needed {
            return;
        }
        run.continuous_reported = true;
        for (index, spec) in self.specs.iter().enumerate() {
            if spec.cadence == Cadence::Continuous
                && self.spec_signature.get(index) == Some(&run.signature)
            {
                on_event(ProgressEvent {
                    tone: spec.tone,
                    spec: Some(index),
                    start: round_position(run.start),
                    sit: None,
                });
            }
        }
    }

    /// Which of the special information tone's frequencies, if any, the
    /// last window of its own bank holds.
    fn classify_sit(&mut self) -> Option<Claim<usize>> {
        let sit_bank = self.sit_bank.window();
        let total = sit_bank.total_power();
        let (band, reading) = (0..SIT_FREQUENCIES.len())
            .filter_map(|i| sit_bank.reading(i).map(|r| (i, r)))
            .max_by(|a, b| a.1.magnitude.total_cmp(&b.1.magnitude))?;
        let offset = reading.offset_hz?;
        let tone = reading.power;
        if offset.abs() > self.config.sit_tolerance_hz
            || tone < self.min_power
            || tone < self.signal_to_noise * (total - tone).max(0.0)
        {
            return None;
        }
        if let Some(acc) = self.sit_offsets.get_mut(band) {
            acc.0 += offset;
            acc.1 += 1.0;
        }
        Some(Claim {
            class: band,
            power: tone,
        })
    }

    fn on_sit_hop(&mut self, hop: Hop<usize>, on_event: &mut impl FnMut(ProgressEvent)) {
        let before = self.sit_previous.replace(hop);
        let h = self.sit_hop_len;
        let hop_start = position_f64(hop.index) * h;
        let bridge = f64::from(SIT_HOP_MS) * 2.0 * self.per_ms;
        if let (Some(band), Some(claim)) = (hop.on(), hop.claim) {
            let coverage = hop.coverage(claim.power);
            let before_coverage = before
                .filter(|b| b.on().is_none())
                .map_or(0.0, |b| b.coverage(claim.power));
            let start = start_edge(hop_start, h, coverage, before_coverage);
            let end = end_edge(hop_start + h, h, coverage, 0.0);
            let continues = self.sit_run.is_some_and(|run| {
                run.band == band && (run.last_on + 1 == hop.index || start - run.end < bridge)
            });
            if continues {
                if let Some(run) = self.sit_run.as_mut() {
                    run.end = end;
                    run.last_on = hop.index;
                    run.last_coverage = coverage;
                    run.last_claim = claim.power;
                }
            } else {
                if let Some(run) = self.sit_run.take() {
                    self.close_sit_run(run, on_event);
                }
                self.sit_run = Some(SitRun {
                    band,
                    start,
                    end,
                    last_on: hop.index,
                    last_coverage: coverage,
                    last_claim: claim.power,
                });
            }
        } else {
            if let Some(run) = self.sit_run.as_mut() {
                if run.last_on + 1 == hop.index {
                    let after = hop.coverage(run.last_claim);
                    run.end = end_edge(hop_start, h, run.last_coverage, after);
                }
                if hop_start + 0.5 * h - run.end >= bridge
                    && let Some(run) = self.sit_run.take()
                {
                    self.close_sit_run(run, on_event);
                }
            }
            let max_gap = f64::from(self.config.sit_max_gap_ms) * self.per_ms;
            if self.sit_run.is_none()
                && self.sit.heard > 0
                && hop_start - self.sit.last_end > max_gap
            {
                self.forget_sit();
            }
        }
    }

    /// One of the three tones has ended: is it the next the sequence wants?
    fn close_sit_run(&mut self, run: SitRun, on_event: &mut impl FnMut(ProgressEvent)) {
        let (shortest, longest) = self.config.sit_duration_ms;
        let length = run.end - run.start;
        let fits = length >= f64::from(shortest) * self.per_ms
            && length <= f64::from(longest) * self.per_ms;
        // the silence before this tone was already held to the longest
        // allowed as it went by, in `on_sit_hop`
        if !(fits && run.band == self.sit.heard) {
            self.forget_sit();
            // a first tone heard out of turn may still begin a sequence
            if fits && run.band == 0 {
                self.accept_sit(run);
            }
            return;
        }
        self.accept_sit(run);
        if self.sit.heard < SIT_FREQUENCIES.len() {
            return;
        }
        let mut frequencies = SIT_FREQUENCIES;
        for (f, (sum, count)) in frequencies.iter_mut().zip(self.sit_offsets) {
            if count > 0.0 {
                *f += sum / count;
            }
        }
        let per_ms = self.per_ms;
        let durations_ms = self
            .sit
            .durations
            .map(|d| u32::try_from(round_position(d / per_ms)).unwrap_or(u32::MAX));
        on_event(ProgressEvent {
            tone: ProgressTone::SpecialInformation,
            spec: None,
            start: round_position(self.sit.start),
            sit: Some(SitMeasurement {
                frequencies,
                durations_ms,
            }),
        });
    }

    fn accept_sit(&mut self, run: SitRun) {
        if self.sit.heard == 0 {
            self.sit.start = run.start;
        }
        if let Some(slot) = self.sit.durations.get_mut(self.sit.heard) {
            *slot = run.end - run.start;
        }
        self.sit.heard += 1;
        self.sit.last_end = run.end;
    }

    fn forget_sit(&mut self) {
        self.sit = SitProgress::default();
        // the tone now sounding, if any, keeps what its windows measured
        let keep = self.sit_run.map(|r| r.band);
        for (band, acc) in self.sit_offsets.iter_mut().enumerate() {
            if Some(band) != keep {
                *acc = (0.0, 0.0);
            }
        }
    }
}

/// Keep a bounded history: the oldest span goes when a new one would not
/// fit.
fn push_span(spans: &mut VecDeque<Span>, span: Span) {
    if spans.len() >= HISTORY {
        spans.pop_front();
        // and the one after it, so the history still starts with a burst
        spans.pop_front();
    }
    spans.push_back(span);
}

/// Whether the latest spans, which end with a burst, match `bursts` for the
/// configured number of cycles and one burst more, starting at any burst of
/// the cadence. Returns the start of the first span matched.
fn matches_cadence(
    spans: &VecDeque<Span>,
    bursts: &[Burst],
    config: &ProgressConfig,
    per_ms: f64,
) -> Option<f64> {
    // the cadence as alternating burst and silence lengths, read in place:
    // this runs at the end of every burst, on the audio thread, and does
    // not allocate
    let nominal = |i: usize| {
        bursts.get(i / 2).map(|b| {
            f64::from(if i.is_multiple_of(2) {
                b.on_ms
            } else {
                b.off_ms
            })
        })
    };
    let period = bursts.len().saturating_mul(2);
    let need = period
        .saturating_mul(usize::try_from(config.cycles).unwrap_or(1))
        .saturating_add(1);
    if period == 0 || spans.len() < need {
        return None;
    }
    let first = spans.len() - need;
    let slack = f64::from(config.cadence_slack_ms);
    (0..bursts.len()).find_map(|rotation| {
        let fits = spans.iter().skip(first).enumerate().all(|(i, span)| {
            nominal((2 * rotation + i) % period).is_some_and(|nominal| {
                let allowed = (nominal * config.cadence_tolerance).max(slack);
                (span.length / per_ms - nominal).abs() <= allowed
            })
        });
        fits.then(|| spans.get(first).map_or(0.0, |s| s.start))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Burst, Cadence, ProgressConfig, ProgressDetector, ProgressEvent, ProgressTone, Region,
        SIT_DURATION_MS, SIT_FREQUENCIES, ToneSpec,
    };
    use crate::inband::SampleRate;
    use crate::inband::dbm0_to_peak;
    use crate::inband::generate::ToneGenerator;
    use crate::inband::signals::{Rng, mix, pair, silence, sine, span, to_pcm, white};

    const RATES: [SampleRate; 2] = [SampleRate::Hz8000, SampleRate::Hz16000];

    fn tone(rate: SampleRate, spec: &ToneSpec, dbm0: f64, ms: u32) -> Vec<i16> {
        let mut out = vec![0_i16; rate.samples(ms)];
        ToneGenerator::new(rate, spec, dbm0).fill(&mut out);
        out
    }

    fn listen_with(
        rate: SampleRate,
        specs: &'static [ToneSpec],
        config: ProgressConfig,
        pcm: &[i16],
    ) -> Vec<ProgressEvent> {
        let mut detector = ProgressDetector::with_config(rate, specs, config);
        let mut events = Vec::new();
        for chunk in pcm.chunks(160) {
            detector.process(chunk, |e| events.push(e));
        }
        events
    }

    fn listen(rate: SampleRate, specs: &'static [ToneSpec], pcm: &[i16]) -> Vec<ProgressEvent> {
        listen_with(rate, specs, ProgressConfig::default(), pcm)
    }

    #[test]
    fn every_tabled_tone_is_heard_as_itself_and_as_nothing_else() {
        for rate in RATES {
            let per_ms = u64::from(rate.hz() / 1_000);
            for region in Region::ALL {
                for (index, spec) in region.tones().iter().enumerate() {
                    let events = listen(rate, region.tones(), &tone(rate, spec, -13.0, 12_000));
                    let context = format!("{rate:?} {region:?} {:?}", spec.tone);
                    assert_eq!(events.len(), 1, "{context}: {events:?}");
                    assert_eq!(events[0].tone, spec.tone, "{context}");
                    assert_eq!(events[0].spec, Some(index), "{context}");
                    assert!(
                        events[0].start <= 5 * per_ms,
                        "{context}: {}",
                        events[0].start
                    );
                }
            }
        }
    }

    #[test]
    fn a_region_does_not_hear_another_regions_busy_tone() {
        // Europe's busy at the United Kingdom's cadence: right rhythm,
        // wrong frequency
        static EUROPE_AT_UK_CADENCE: [ToneSpec; 1] = [ToneSpec {
            tone: ProgressTone::Busy,
            frequencies: &[425.0],
            cadence: Cadence::Repeating(&[Burst {
                on_ms: 375,
                off_ms: 375,
            }]),
        }];
        for rate in RATES {
            let pcm = tone(rate, &EUROPE_AT_UK_CADENCE[0], -13.0, 6_000);
            let heard = listen(rate, Region::UnitedKingdom.tones(), &pcm);
            assert!(heard.is_empty(), "{rate:?}: {heard:?}");
            let heard = listen(rate, &EUROPE_AT_UK_CADENCE, &pcm);
            assert_eq!(
                heard.len(),
                1,
                "{rate:?}: the same audio against its own spec"
            );
        }
    }

    /// 425 Hz switched on for `on` ms and off for `off` ms, five times.
    fn cadence(rate: SampleRate, on: f64, off: f64) -> Vec<i16> {
        let hz = rate.hz();
        let mut signal = Vec::new();
        for _ in 0..5 {
            signal.extend(sine(425.0, dbm0_to_peak(-13.0), 0.0, hz, span(hz, on)));
            signal.extend(silence(span(hz, off)));
        }
        to_pcm(&signal)
    }

    #[test]
    fn a_cadence_inside_its_tolerance_is_heard_and_one_outside_it_is_not() {
        for rate in RATES {
            let tones = |on, off| -> Vec<ProgressTone> {
                listen(rate, Region::Europe.tones(), &cadence(rate, on, off))
                    .iter()
                    .map(|e| e.tone)
                    .collect()
            };
            // busy is 500 ms either way, allowed 100
            assert_eq!(tones(590.0, 410.0), [ProgressTone::Busy], "{rate:?}");
            assert_eq!(tones(410.0, 590.0), [ProgressTone::Busy], "{rate:?}");
            assert!(tones(620.0, 500.0).is_empty(), "{rate:?}");
            assert!(tones(500.0, 380.0).is_empty(), "{rate:?}");
            // congestion is 250 ms, allowed 50
            assert_eq!(tones(290.0, 210.0), [ProgressTone::Congestion], "{rate:?}");
            assert!(tones(250.0, 320.0).is_empty(), "{rate:?}");
        }
    }

    #[test]
    fn a_short_burst_is_allowed_the_slack_where_a_fraction_would_be_too_little() {
        // the United Kingdom's call waiting is 100 ms: a fifth is 20 ms,
        // and the 40 ms of slack is what applies
        let rate = SampleRate::Hz8000;
        let hz = rate.hz();
        let mut signal = Vec::new();
        for _ in 0..3 {
            signal.extend(sine(400.0, dbm0_to_peak(-13.0), 0.0, hz, span(hz, 135.0)));
            signal.extend(silence(span(hz, 1_990.0)));
        }
        let events = listen(rate, Region::UnitedKingdom.tones(), &to_pcm(&signal));
        assert_eq!(
            events.iter().map(|e| e.tone).collect::<Vec<_>>(),
            [ProgressTone::CallWaiting]
        );
        let config = ProgressConfig {
            cadence_slack_ms: 0,
            ..ProgressConfig::default()
        };
        assert!(
            listen_with(
                rate,
                Region::UnitedKingdom.tones(),
                config,
                &to_pcm(&signal)
            )
            .is_empty()
        );
    }

    #[test]
    fn ringing_is_not_taken_for_a_dial_tone_and_a_dial_tone_waits_its_time() {
        for rate in RATES {
            let dial = &Region::NorthAmerica.tones()[0];
            let events = listen(
                rate,
                Region::NorthAmerica.tones(),
                &tone(rate, dial, -13.0, 2_400),
            );
            assert!(
                events.is_empty(),
                "{rate:?}: 2.4 s is under the 2.5 s asked for"
            );
            let events = listen(
                rate,
                Region::NorthAmerica.tones(),
                &tone(rate, dial, -13.0, 2_700),
            );
            assert_eq!(events.len(), 1, "{rate:?}");
        }
    }

    #[test]
    fn two_cycles_asked_for_wait_for_two() {
        let rate = SampleRate::Hz8000;
        let busy = &Region::Europe.tones()[2];
        let config = ProgressConfig {
            cycles: 2,
            ..ProgressConfig::default()
        };
        // a cycle and the burst after it is enough for one, not for two
        let pcm = tone(rate, busy, -13.0, 1_700);
        assert_eq!(listen(rate, Region::Europe.tones(), &pcm).len(), 1);
        assert!(listen_with(rate, Region::Europe.tones(), config, &pcm).is_empty());
        let pcm = tone(rate, busy, -13.0, 2_700);
        assert_eq!(
            listen_with(rate, Region::Europe.tones(), config, &pcm).len(),
            1
        );
    }

    #[test]
    fn a_tone_just_above_the_level_floor_is_heard_and_just_below_it_is_not() {
        for rate in RATES {
            let busy = &Region::Europe.tones()[2];
            assert_eq!(
                listen(
                    rate,
                    Region::Europe.tones(),
                    &tone(rate, busy, -36.0, 3_000)
                )
                .len(),
                1
            );
            assert!(
                listen(
                    rate,
                    Region::Europe.tones(),
                    &tone(rate, busy, -40.0, 3_000)
                )
                .is_empty()
            );
        }
    }

    #[test]
    fn a_tone_missing_one_of_its_pair_is_not_that_tone() {
        for rate in RATES {
            let hz = rate.hz();
            let mut signal = Vec::new();
            for _ in 0..3 {
                // North American busy with its 620 Hz half 12 dB down
                signal.extend(pair((480.0, -13.0), (620.0, -25.0), hz, span(hz, 500.0)));
                signal.extend(silence(span(hz, 500.0)));
            }
            let events = listen(rate, Region::NorthAmerica.tones(), &to_pcm(&signal));
            assert!(events.is_empty(), "{rate:?}: {events:?}");
            let mut signal = Vec::new();
            for _ in 0..3 {
                signal.extend(pair((480.0, -13.0), (620.0, -20.0), hz, span(hz, 500.0)));
                signal.extend(silence(span(hz, 500.0)));
            }
            let events = listen(rate, Region::NorthAmerica.tones(), &to_pcm(&signal));
            assert_eq!(
                events.len(),
                1,
                "{rate:?}: 7 dB down is inside the 10 allowed"
            );
        }
    }

    #[test]
    fn a_tone_under_a_louder_sound_is_not_heard_and_over_a_quieter_one_is() {
        for rate in RATES {
            let hz = rate.hz();
            let busy = &Region::UnitedKingdom.tones()[2];
            for (relative, heard) in [(-10.0, true), (0.0, false)] {
                let pcm = tone(rate, busy, -13.0, 3_000);
                let mut signal: Vec<f64> = pcm.iter().map(|&s| f64::from(s)).collect();
                let other = sine(
                    1_000.0,
                    dbm0_to_peak(-13.0 + relative),
                    0.0,
                    hz,
                    signal.len(),
                );
                mix(&mut signal, &other);
                let events = listen(rate, Region::UnitedKingdom.tones(), &to_pcm(&signal));
                assert_eq!(
                    events.len(),
                    usize::from(heard),
                    "{rate:?} {relative} dB: {events:?}"
                );
            }
        }
    }

    #[test]
    fn busy_is_heard_through_noise() {
        let mut rng = Rng::new(3);
        for rate in RATES {
            let busy = &Region::UnitedKingdom.tones()[2];
            let pcm = tone(rate, busy, -13.0, 3_000);
            let mut signal: Vec<f64> = pcm.iter().map(|&s| f64::from(s)).collect();
            let noise = white(&mut rng, -26.0, signal.len());
            mix(&mut signal, &noise);
            let events = listen(rate, Region::UnitedKingdom.tones(), &to_pcm(&signal));
            assert_eq!(
                events.iter().map(|e| e.tone).collect::<Vec<_>>(),
                [ProgressTone::Busy],
                "{rate:?}"
            );
        }
    }

    fn sit(rate: SampleRate, frequencies: [f64; 3], durations: [f64; 3], gap: f64) -> Vec<i16> {
        to_pcm(&sit_at(rate, frequencies, durations, gap, -15.0))
    }

    fn sit_at(
        rate: SampleRate,
        frequencies: [f64; 3],
        durations: [f64; 3],
        gap: f64,
        dbm0: f64,
    ) -> Vec<f64> {
        let hz = rate.hz();
        let mut signal = silence(span(hz, 200.0));
        for _ in 0..2 {
            for (&f, &ms) in frequencies.iter().zip(&durations) {
                signal.extend(sine(f, dbm0_to_peak(dbm0), 0.0, hz, span(hz, ms)));
                signal.extend(silence(span(hz, gap)));
            }
            signal.extend(silence(span(hz, 1_000.0)));
        }
        signal
    }

    fn sits(rate: SampleRate, pcm: &[i16]) -> Vec<ProgressEvent> {
        listen(rate, Region::Europe.tones(), pcm)
            .into_iter()
            .filter(|e| e.tone == ProgressTone::SpecialInformation)
            .collect()
    }

    #[test]
    fn the_special_information_tone_is_heard_and_measured() {
        for rate in RATES {
            let per_ms = f64::from(rate.hz()) / 1_000.0;
            let mut generated = vec![0_i16; rate.samples(2 * (990 + 1_000))];
            ToneGenerator::special_information(rate, SIT_FREQUENCIES, SIT_DURATION_MS, -15.0)
                .fill(&mut generated);
            let events = sits(rate, &generated);
            assert_eq!(events.len(), 2, "{rate:?}: once per repetition: {events:?}");
            assert!(f64::from(u32::try_from(events[0].start).unwrap()) / per_ms < 1.0);
            let measured = events[0].sit.unwrap();
            for (f, nominal) in measured.frequencies.iter().zip(SIT_FREQUENCIES) {
                assert!((f - nominal).abs() < 2.0, "{rate:?}: {f} for {nominal}");
            }
            for d in measured.durations_ms {
                assert!(d.abs_diff(330) <= 2, "{rate:?}: {d} ms");
            }
        }
    }

    #[test]
    fn a_north_american_variant_is_heard_with_its_own_frequencies_and_lengths() {
        for rate in RATES {
            let events = sits(
                rate,
                &sit(rate, [913.8, 1_370.6, 1_776.7], [274.0, 274.0, 380.0], 0.0),
            );
            assert_eq!(events.len(), 2, "{rate:?}: {events:?}");
            let measured = events[0].sit.unwrap();
            for (f, expected) in measured.frequencies.iter().zip([913.8, 1_370.6, 1_776.7]) {
                assert!((f - expected).abs() < 2.0, "{rate:?}: {f} for {expected}");
            }
            for (d, expected) in measured.durations_ms.iter().zip([274, 274, 380]) {
                assert!(d.abs_diff(expected) <= 2, "{rate:?}: {d} for {expected}");
            }
        }
    }

    #[test]
    fn the_special_information_tone_is_refused_outside_each_of_its_tolerances() {
        let nominal = [950.0, 1_400.0, 1_800.0];
        for rate in RATES {
            assert_eq!(
                sits(rate, &sit(rate, nominal, [330.0; 3], 0.0)).len(),
                2,
                "{rate:?}"
            );
            assert_eq!(
                sits(rate, &sit(rate, nominal, [330.0; 3], 25.0)).len(),
                2,
                "{rate:?} 25 ms gaps"
            );
            assert_eq!(
                sits(rate, &sit(rate, nominal, [265.0, 330.0, 395.0], 0.0)).len(),
                2,
                "{rate:?} 330 ± 65"
            );
            assert_eq!(
                sits(rate, &sit(rate, [995.0, 1_355.0, 1_845.0], [330.0; 3], 0.0)).len(),
                2,
                "{rate:?} ± 45 Hz"
            );
            let refused = [
                (
                    "out of order",
                    sit(rate, [1_400.0, 950.0, 1_800.0], [330.0; 3], 0.0),
                ),
                ("too short", sit(rate, nominal, [330.0, 200.0, 330.0], 0.0)),
                ("too long", sit(rate, nominal, [330.0, 330.0, 480.0], 0.0)),
                ("a gap", sit(rate, nominal, [330.0; 3], 100.0)),
                (
                    "off frequency",
                    sit(rate, [950.0, 1_470.0, 1_800.0], [330.0; 3], 0.0),
                ),
            ];
            for (what, pcm) in refused {
                let events = sits(rate, &pcm);
                assert!(events.is_empty(), "{rate:?} {what}: {events:?}");
            }
        }
    }

    #[test]
    fn the_special_information_tone_is_held_to_the_level_and_noise_floors() {
        for rate in RATES {
            let hz = rate.hz();
            let at = |dbm0| {
                sits(
                    rate,
                    &to_pcm(&sit_at(rate, SIT_FREQUENCIES, [330.0; 3], 0.0, dbm0)),
                )
                .len()
            };
            assert_eq!(at(-36.0), 2, "{rate:?}");
            assert_eq!(at(-40.0), 0, "{rate:?}");
            for (relative, heard) in [(-10.0, 2), (0.0, 0)] {
                let mut signal = sit_at(rate, SIT_FREQUENCIES, [330.0; 3], 0.0, -15.0);
                let other = sine(600.0, dbm0_to_peak(-15.0 + relative), 0.0, hz, signal.len());
                mix(&mut signal, &other);
                assert_eq!(
                    sits(rate, &to_pcm(&signal)).len(),
                    heard,
                    "{rate:?} {relative} dB"
                );
            }
        }
    }

    #[test]
    fn a_cadence_broken_off_and_resumed_is_reported_again() {
        for rate in RATES {
            let tones = Region::Europe.tones();
            let (dial, busy) = (&tones[0], &tones[2]);
            let mut pcm = tone(rate, busy, -13.0, 3_000);
            pcm.extend(vec![0_i16; rate.samples(1_000)]);
            pcm.extend(tone(rate, dial, -13.0, 3_000));
            pcm.extend(vec![0_i16; rate.samples(1_000)]);
            pcm.extend(tone(rate, busy, -13.0, 3_000));
            let heard: Vec<ProgressTone> =
                listen(rate, tones, &pcm).iter().map(|e| e.tone).collect();
            assert_eq!(
                heard,
                [ProgressTone::Busy, ProgressTone::Dial, ProgressTone::Busy],
                "{rate:?}"
            );
        }
    }

    #[test]
    fn reset_forgets_a_cadence_half_heard() {
        let rate = SampleRate::Hz8000;
        let busy = &Region::Europe.tones()[2];
        let pcm = tone(rate, busy, -13.0, 900);
        let mut detector = ProgressDetector::new(rate, Region::Europe.tones());
        let mut events = Vec::new();
        detector.process(&pcm, |e| events.push(e));
        detector.reset();
        detector.process(&pcm, |e| events.push(e));
        assert!(events.is_empty(), "{events:?}");
        assert_eq!(detector.specs().len(), 5);
        assert_eq!(detector.config().cycles, 1);
    }

    #[test]
    fn cycles_are_held_to_their_range() {
        let config = ProgressConfig {
            cycles: 99,
            ..ProgressConfig::default()
        };
        let detector =
            ProgressDetector::with_config(SampleRate::Hz8000, Region::Europe.tones(), config);
        assert_eq!(detector.config().cycles, 4);
        let config = ProgressConfig {
            cycles: 0,
            ..ProgressConfig::default()
        };
        let detector =
            ProgressDetector::with_config(SampleRate::Hz8000, Region::Europe.tones(), config);
        assert_eq!(detector.config().cycles, 1);
    }
}
