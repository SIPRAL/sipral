// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Keypad digits found in decoded audio.
//!
//! A digit is two sines sounding together, one from a low group of four
//! frequencies and one from a high group of four, as ITU-T Q.23 lays them
//! out. Finding one is easy; the work is in refusing everything that is not
//! one, and ITU-T Q.24 Annex A says where the line sits. Its Table A-1
//! collects the receiver limits of the networks it surveyed, and where they
//! differ the defaults here take the North American column, which most
//! equipment follows (RFC 4733 §3.1 quotes the same table for the 40 ms of
//! tone and of pause it expects):
//!
//! | limit | must accept | must refuse | default here |
//! |---|---|---|---|
//! | frequency deviation | within ±1.5 % | beyond ±3.5 % | decides at ±2.5 % |
//! | high group louder than low | up to 4 dB | | 4 dB |
//! | low group louder than high | up to 8 dB | | 8 dB |
//! | level, each frequency | down to −25 dBm0 | −55 dBm0 and below | −30 dBm0 |
//! | tone duration | 40 ms and more | 23 ms and less | decides at 32 ms |
//! | pause between digits | 40 ms and more | | |
//! | interruption inside a digit | | 10 ms and less splits nothing | decides at 25 ms |
//!
//! Where the table leaves a band between accepting and refusing, the
//! default sits inside it, away from both edges, so that the measuring error
//! of a real signal cannot carry a tone across. Every limit is a field of
//! [`DtmfConfig`].
//!
//! # Talk-off
//!
//! Speech that happens to put energy at a row and a column frequency must
//! not dial. Three tests stand in its way besides the ones above. The two
//! tones have to carry nearly all of the power in the window — ten times
//! what is left over, by default — which a voice with a dozen harmonics
//! across the band cannot. Neither tone may have a strong second harmonic,
//! which a voiced sound always has and a generator conforming to Q.23 does
//! not: that Recommendation holds unwanted components 20 dB under the
//! fundamental, and the default here refuses anything within 15. And a tone
//! has to hold still, in frequency as well as level. Each window's
//! frequency is measured afresh, and a window that hears the same digit as
//! the one a hop before it counts only if neither tone has moved further
//! than a steady rate of crossing its whole acceptance band in the shortest
//! digit would take it. Without that, a pair gliding through both bands
//! together, inside them for 20 ms, was a digit: every 20 ms window that
//! overlaps those 20 ms reads the tones inside the band, and the windows
//! together cover more than the shortest digit.
//!
//! # How it listens
//!
//! A 20 ms Hann window slides along the audio 5 ms at a time. Twenty
//! milliseconds is the shortest window that still resolves the two closest
//! frequencies of a group — 697 and 770 Hz are 1.46 bins apart, and the
//! lower one leaks into the upper's filter 14 dB down — and the 5 ms hop
//! does three things: it places each edge of a tone within a hop before the
//! energy of that hop narrows it further, it keeps a 23 ms tone and a 40 ms
//! one several hops apart, and it lets the phase each filter turns through
//! between windows read frequency unambiguously within ±100 Hz, beyond the
//! ±57 Hz that 3.5 % of the highest frequency, 1633 Hz, amounts to. The
//! window and hop are the same length of time at 8 and 16 kHz, so the
//! behaviour is too; see the `analysis` module for the arithmetic.
//!
//! # A digit that also arrived as an event
//!
//! A gateway that sends a key as an RFC 4733 event does not always take the
//! tone out of the audio, so the same press can arrive twice. The detector
//! reports each digit's start and end on the stream's own sample clock, and
//! [`KeyPress`] puts that and a telephone event side by side:
//! [`KeyPress::is_same_press`] says whether two reports are one key.

use super::analysis::{Analyzer, Claim, Hop, HopTracker, end_edge, start_edge};
use super::{SampleRate, count_f64, dbm0_to_power, position_f64, round_position};

/// The four low-group frequencies of Q.23, in hertz: the rows of the keypad.
pub const LOW_GROUP: [f64; 4] = [697.0, 770.0, 852.0, 941.0];

/// The four high-group frequencies of Q.23, in hertz: the columns.
pub const HIGH_GROUP: [f64; 4] = [1_209.0, 1_336.0, 1_477.0, 1_633.0];

const WINDOW_MS: u32 = 20;
const HOP_MS: u32 = 5;

/// One key of the sixteen-key pad of Q.23.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Digit {
    /// `0`
    Zero,
    /// `1`
    One,
    /// `2`
    Two,
    /// `3`
    Three,
    /// `4`
    Four,
    /// `5`
    Five,
    /// `6`
    Six,
    /// `7`
    Seven,
    /// `8`
    Eight,
    /// `9`
    Nine,
    /// `*`
    Star,
    /// `#`
    Hash,
    /// `A`, the fourth column's first row.
    A,
    /// `B`
    B,
    /// `C`
    C,
    /// `D`
    D,
}

/// The keypad, row by row: `KEYPAD[row][column]` sounds `LOW_GROUP[row]`
/// and `HIGH_GROUP[column]`.
const KEYPAD: [[Digit; 4]; 4] = [
    [Digit::One, Digit::Two, Digit::Three, Digit::A],
    [Digit::Four, Digit::Five, Digit::Six, Digit::B],
    [Digit::Seven, Digit::Eight, Digit::Nine, Digit::C],
    [Digit::Star, Digit::Zero, Digit::Hash, Digit::D],
];

impl Digit {
    /// All sixteen, in RFC 4733 event-code order.
    pub const ALL: [Self; 16] = [
        Self::Zero,
        Self::One,
        Self::Two,
        Self::Three,
        Self::Four,
        Self::Five,
        Self::Six,
        Self::Seven,
        Self::Eight,
        Self::Nine,
        Self::Star,
        Self::Hash,
        Self::A,
        Self::B,
        Self::C,
        Self::D,
    ];

    /// The key a character names: `0`–`9`, `*`, `#`, and `A`–`D` in either
    /// case.
    #[must_use]
    pub const fn from_char(c: char) -> Option<Self> {
        Some(match c {
            '0' => Self::Zero,
            '1' => Self::One,
            '2' => Self::Two,
            '3' => Self::Three,
            '4' => Self::Four,
            '5' => Self::Five,
            '6' => Self::Six,
            '7' => Self::Seven,
            '8' => Self::Eight,
            '9' => Self::Nine,
            '*' => Self::Star,
            '#' => Self::Hash,
            'A' | 'a' => Self::A,
            'B' | 'b' => Self::B,
            'C' | 'c' => Self::C,
            'D' | 'd' => Self::D,
            _ => return None,
        })
    }

    /// The character printed on the key.
    #[must_use]
    pub const fn to_char(self) -> char {
        match self {
            Self::Zero => '0',
            Self::One => '1',
            Self::Two => '2',
            Self::Three => '3',
            Self::Four => '4',
            Self::Five => '5',
            Self::Six => '6',
            Self::Seven => '7',
            Self::Eight => '8',
            Self::Nine => '9',
            Self::Star => '*',
            Self::Hash => '#',
            Self::A => 'A',
            Self::B => 'B',
            Self::C => 'C',
            Self::D => 'D',
        }
    }

    /// The RFC 4733 §3.2 event code: 0–9 for the digits, 10 for `*`, 11 for
    /// `#`, 12–15 for `A`–`D`.
    #[must_use]
    pub const fn event_code(self) -> u8 {
        match self {
            Self::Zero => 0,
            Self::One => 1,
            Self::Two => 2,
            Self::Three => 3,
            Self::Four => 4,
            Self::Five => 5,
            Self::Six => 6,
            Self::Seven => 7,
            Self::Eight => 8,
            Self::Nine => 9,
            Self::Star => 10,
            Self::Hash => 11,
            Self::A => 12,
            Self::B => 13,
            Self::C => 14,
            Self::D => 15,
        }
    }

    /// The key an RFC 4733 event code names, if it names a key: codes past
    /// 15 are other telephone events.
    #[must_use]
    pub fn from_event_code(code: u8) -> Option<Self> {
        Self::ALL.get(usize::from(code)).copied()
    }

    /// The key's row and column on the pad.
    const fn position(self) -> (usize, usize) {
        match self {
            Self::One => (0, 0),
            Self::Two => (0, 1),
            Self::Three => (0, 2),
            Self::A => (0, 3),
            Self::Four => (1, 0),
            Self::Five => (1, 1),
            Self::Six => (1, 2),
            Self::B => (1, 3),
            Self::Seven => (2, 0),
            Self::Eight => (2, 1),
            Self::Nine => (2, 2),
            Self::C => (2, 3),
            Self::Star => (3, 0),
            Self::Zero => (3, 1),
            Self::Hash => (3, 2),
            Self::D => (3, 3),
        }
    }

    /// The low- and high-group frequencies of the key, in hertz.
    #[must_use]
    pub fn frequencies(self) -> (f64, f64) {
        let (row, column) = self.position();
        (
            LOW_GROUP.get(row).copied().unwrap_or_default(),
            HIGH_GROUP.get(column).copied().unwrap_or_default(),
        )
    }

    fn at(row: usize, column: usize) -> Option<Self> {
        KEYPAD.get(row).and_then(|r| r.get(column)).copied()
    }
}

/// The acceptance limits of a [`DtmfDetector`]. The module docs give the
/// Q.24 figure behind each default.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DtmfConfig {
    /// The largest deviation of either tone from its nominal frequency, as a
    /// fraction: 0.025 is ±2.5 %, between the ±1.5 % Q.24 has a receiver
    /// accept and the ±3.5 % it has one refuse.
    pub max_frequency_deviation: f64,
    /// How much louder the high-group tone may be than the low, in dB, as a
    /// sender that pre-emphasises the high group makes it: what Q.24 calls
    /// a positive level difference. Default 4 dB. The trade names the two
    /// directions of twist both ways round, so these fields say instead
    /// which tone is the louder.
    pub max_high_over_low_db: f64,
    /// How much louder the low-group tone may be than the high, in dB: what
    /// a long line's loss at high frequency produces.
    /// Default 8 dB.
    pub max_low_over_high_db: f64,
    /// The least level, in dBm0, either tone may have. Default −30 dBm0:
    /// below the −25 dBm0 Q.24's North American column has a receiver
    /// operate at, far above the −55 dBm0 it must ignore.
    pub min_level_dbm0: f64,
    /// How far the two tones together must stand above everything else in
    /// the window, in dB. Default 10 dB. This is the main defence against
    /// talk-off; Q.24 leaves noise to the administrations, so the value is
    /// a judgement, and the module tests measure both sides of it.
    pub min_signal_to_noise_db: f64,
    /// The strongest second harmonic either tone may carry, in dB relative
    /// to that tone. Q.23 has a sender keep unwanted components 20 dB down,
    /// and Q.24 sets no receiver limit; default −15 dB, a judgement. A
    /// harmonic 58 to 71 Hz from the column tone, as twice 697, 770 or
    /// 852 Hz is for the column beside it, reads up to 1.5 dB low.
    pub max_second_harmonic_db: f64,
    /// The shortest tone that is a digit, in milliseconds. Q.24 has a
    /// receiver accept 40 ms and refuse 23 ms; default 32.
    pub min_tone_ms: u32,
    /// The shortest silence that separates two presses of the same key, in
    /// milliseconds. A shorter break is an interruption inside one digit.
    /// Q.24 has a receiver bridge 10 ms and recognise a 40 ms pause;
    /// default 25.
    pub min_pause_ms: u32,
}

impl Default for DtmfConfig {
    fn default() -> Self {
        Self {
            max_frequency_deviation: 0.025,
            max_high_over_low_db: 4.0,
            max_low_over_high_db: 8.0,
            min_level_dbm0: -30.0,
            min_signal_to_noise_db: 10.0,
            max_second_harmonic_db: -15.0,
            min_tone_ms: 32,
            min_pause_ms: 25,
        }
    }
}

/// What a [`DtmfDetector`] reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DtmfEvent {
    /// A digit has lasted long enough to be one. `start` is the sample its
    /// tones began at, which is earlier than the sample that completed the
    /// decision by at least the minimum duration.
    Start {
        /// Which key.
        digit: Digit,
        /// The first sample of the tone.
        start: u64,
    },
    /// The digit has ended. Reported once the pause after it is long enough
    /// that it cannot be an interruption, so some tens of milliseconds after
    /// `end`. Always preceded by the matching [`DtmfEvent::Start`].
    End {
        /// Which key.
        digit: Digit,
        /// The first sample of the tone, as its start reported it.
        start: u64,
        /// The sample after the tone's last.
        end: u64,
    },
}

impl DtmfEvent {
    /// The digit the event is about.
    #[must_use]
    pub const fn digit(&self) -> Digit {
        match *self {
            Self::Start { digit, .. } | Self::End { digit, .. } => digit,
        }
    }

    /// The press as far as this event knows it: a start alone is a press
    /// with no length yet.
    #[must_use]
    pub const fn key_press(&self) -> KeyPress {
        match *self {
            Self::Start { digit, start } => KeyPress {
                digit,
                start,
                end: start,
            },
            Self::End { digit, start, end } => KeyPress { digit, start, end },
        }
    }
}

/// One key press, in samples on some stream's clock, whichever way it was
/// heard: from a [`DtmfEvent`], or from an RFC 4733 telephone event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyPress {
    /// Which key.
    pub digit: Digit,
    /// The first sample of the press.
    pub start: u64,
    /// The sample after its last, or `start` when the length is not known
    /// yet.
    pub end: u64,
}

impl KeyPress {
    /// The press an RFC 4733 event describes: its event code, the sample its
    /// timestamp names, and its duration in samples.
    ///
    /// The detector counts samples at the rate it was built for from the
    /// first it was given; a telephone event is timestamped in the RTP
    /// clock of its stream, which for G.722 ticks at 8 kHz though the audio
    /// is 16 kHz (RFC 3551 §4.5.2). Mapping one onto the other is the
    /// caller's, and `start` and `duration` here are after it.
    #[must_use]
    pub fn from_telephone_event(event: u8, start: u64, duration: u64) -> Option<Self> {
        Digit::from_event_code(event).map(|digit| Self {
            digit,
            start,
            end: start.saturating_add(duration),
        })
    }

    /// Whether two reports describe one press: the same key, over spans
    /// that overlap once each is widened by `tolerance` samples at either
    /// end. Sixty milliseconds of tolerance covers the slack between a
    /// gateway's event timestamp and the tone it leaves in the audio
    /// without joining two presses a keypad can produce, which Q.24 puts at
    /// least 40 ms of pause apart.
    #[must_use]
    pub fn is_same_press(&self, other: &Self, tolerance: u64) -> bool {
        self.digit == other.digit
            && self.start <= other.end.saturating_add(tolerance)
            && other.start <= self.end.saturating_add(tolerance)
    }
}

/// A digit being heard.
#[derive(Clone, Copy, Debug)]
struct Open {
    digit: Digit,
    start: f64,
    end: f64,
    last_on: u64,
    last_coverage: f64,
    last_claim: f64,
    reported: bool,
}

/// Limits turned into the linear ratios the per-window test compares.
#[derive(Clone, Copy, Debug)]
struct Limits {
    deviation: f64,
    high_over_low: f64,
    low_over_high: f64,
    min_power: f64,
    signal_to_noise: f64,
    harmonic: f64,
    min_tone: f64,
    min_pause: f64,
    /// The most either tone may move from one window to the next, as a
    /// fraction of its nominal frequency.
    drift: f64,
}

impl Limits {
    fn new(config: &DtmfConfig, rate: SampleRate) -> Self {
        let per_ms = rate.as_f64() / 1_000.0;
        Self {
            deviation: config.max_frequency_deviation,
            high_over_low: from_db(config.max_high_over_low_db),
            low_over_high: from_db(config.max_low_over_high_db),
            min_power: dbm0_to_power(config.min_level_dbm0),
            signal_to_noise: from_db(config.min_signal_to_noise_db),
            harmonic: from_db(config.max_second_harmonic_db),
            min_tone: f64::from(config.min_tone_ms) * per_ms,
            min_pause: f64::from(config.min_pause_ms) * per_ms,
            // a tone that could cross the whole band it is accepted in
            // within the shortest digit is not holding still for one
            drift: 2.0 * config.max_frequency_deviation * f64::from(HOP_MS)
                / f64::from(config.min_tone_ms.max(1)),
        }
    }
}

/// What one window heard, when it heard a digit: the claim, and the two
/// frequencies it measured.
#[derive(Clone, Copy, Debug)]
struct Heard {
    claim: Claim<Digit>,
    low_hz: f64,
    high_hz: f64,
}

fn from_db(db: f64) -> f64 {
    10f64.powf(db / 10.0)
}

/// Finds DTMF digits in one stream of decoded audio.
#[derive(Clone, Debug)]
pub struct DtmfDetector {
    config: DtmfConfig,
    limits: Limits,
    rate: SampleRate,
    analyzer: Analyzer,
    hops: HopTracker<Digit>,
    hop_len: f64,
    previous: Option<Hop<Digit>>,
    open: Option<Open>,
    /// What the last window heard, if it heard a digit.
    last: Option<Heard>,
}

impl DtmfDetector {
    /// A detector at `rate` with the default limits.
    #[must_use]
    pub fn new(rate: SampleRate) -> Self {
        Self::with_config(rate, DtmfConfig::default())
    }

    /// A detector with explicit limits.
    #[must_use]
    pub fn with_config(rate: SampleRate, config: DtmfConfig) -> Self {
        let frequencies: Vec<f64> = LOW_GROUP.iter().chain(&HIGH_GROUP).copied().collect();
        let analyzer = Analyzer::new(rate, WINDOW_MS, HOP_MS, &frequencies);
        let hops = HopTracker::new(analyzer.hops_per_window());
        let hop_len = count_f64(analyzer.hop());
        Self {
            limits: Limits::new(&config, rate),
            config,
            rate,
            analyzer,
            hops,
            hop_len,
            previous: None,
            open: None,
            last: None,
        }
    }

    /// The limits the detector was built with.
    #[must_use]
    pub const fn config(&self) -> &DtmfConfig {
        &self.config
    }

    /// The rate the detector expects.
    #[must_use]
    pub const fn sample_rate(&self) -> SampleRate {
        self.rate
    }

    /// Forget the stream, including a digit being heard, which is dropped
    /// without an end: the next sample is sample zero of a new stream.
    pub fn reset(&mut self) {
        self.analyzer.reset();
        self.hops.reset();
        self.previous = None;
        self.open = None;
        self.last = None;
    }

    /// Listen to `samples`, the next ones of the stream, and report every
    /// digit start and end they complete.
    pub fn process(&mut self, samples: &[i16], mut on_event: impl FnMut(DtmfEvent)) {
        for &sample in samples {
            if self.analyzer.push(sample) {
                let heard = self.classify();
                let claim = heard.and_then(|h| self.is_steady(&h).then_some(h.claim));
                self.last = heard;
                let hop =
                    self.hops
                        .push(self.analyzer.hop_index(), self.analyzer.hop_power(), claim);
                if let Some(hop) = hop {
                    self.on_hop(hop, &mut on_event);
                }
            }
        }
    }

    /// The stream has ended: settle what the last few milliseconds held and
    /// close a digit still sounding, reporting its end at the last sample
    /// the detector could place it. The detector is then as
    /// [`reset`](Self::reset) leaves it.
    pub fn finish(&mut self, mut on_event: impl FnMut(DtmfEvent)) {
        while let Some(hop) = self.hops.drain_one() {
            self.on_hop(hop, &mut on_event);
        }
        if let Some(open) = self.open.take() {
            self.close(open, &mut on_event);
        }
        self.reset();
    }

    /// Whether `heard` holds still against the window before it: a window
    /// that heard the same digit a hop earlier must have heard both tones
    /// within the drift allowed of where this one hears them. The first
    /// window of a digit has nothing to be compared with.
    fn is_steady(&self, heard: &Heard) -> bool {
        let (low, high) = heard.claim.class.frequencies();
        let drift = self.limits.drift;
        self.last.is_none_or(|last| {
            last.claim.class != heard.claim.class
                || ((heard.low_hz - last.low_hz).abs() <= drift * low
                    && (heard.high_hz - last.high_hz).abs() <= drift * high)
        })
    }

    /// What the window just analysed holds, if it holds a digit.
    fn classify(&self) -> Option<Heard> {
        let bank = &self.analyzer;
        let limits = &self.limits;
        let total = bank.total_power();
        if total < 2.0 * limits.min_power {
            return None;
        }
        let (row, low) = strongest(bank, 0)?;
        let (column, high) = strongest(bank, 4)?;
        let low_nominal = LOW_GROUP.get(row).copied()?;
        let high_nominal = HIGH_GROUP.get(column).copied()?;

        let low_offset = low.offset_hz?;
        let high_offset = high.offset_hz?;
        if low_offset.abs() > limits.deviation * low_nominal
            || high_offset.abs() > limits.deviation * high_nominal
        {
            return None;
        }

        let (low_power, high_power) = (low.power, high.power);
        if low_power < limits.min_power || high_power < limits.min_power {
            return None;
        }
        if high_power > limits.high_over_low * low_power
            || low_power > limits.low_over_high * high_power
        {
            return None;
        }

        let tone = low_power + high_power;
        let rest = (total - tone).max(0.0);
        if tone < limits.signal_to_noise * rest {
            return None;
        }

        let tones = [
            (row, low_nominal + low_offset, low_power),
            (4 + column, high_nominal + high_offset, high_power),
        ];
        for &(_, frequency, power) in &tones {
            let harmonic = 2.0 * frequency;
            // the two tones leak into the harmonic's filter too — 697 Hz's
            // second harmonic sits 58 Hz from 1336 Hz — and that is not
            // harmonic, so what they put there is taken off first
            let (re, im, coupling) =
                tones
                    .iter()
                    .fold((0.0, 0.0, 0.0), |(re, im, coupling), &(bin, f, _)| {
                        let leak = bank.leak(bin, f, harmonic);
                        (re + leak.dft.0, im + leak.dft.1, coupling + leak.coupling)
                    });
            let (heard_re, heard_im) = bank.probe(harmonic);
            let left = (heard_re - re).hypot(heard_im - im) / (1.0 - coupling).max(0.1);
            let own = bank.amplitude_at_centre(left);
            if own * own / 2.0 > limits.harmonic * power {
                return None;
            }
        }

        Digit::at(row, column).map(|class| Heard {
            claim: Claim { class, power: tone },
            low_hz: low_nominal + low_offset,
            high_hz: high_nominal + high_offset,
        })
    }

    fn hop_start(&self, index: u64) -> f64 {
        position_f64(index) * self.hop_len
    }

    fn on_hop(&mut self, hop: Hop<Digit>, on_event: &mut impl FnMut(DtmfEvent)) {
        let before = self.previous.replace(hop);
        if let (Some(digit), Some(claim)) = (hop.on(), hop.claim) {
            self.on_tone(hop, digit, claim.power, before, on_event);
        } else {
            self.on_quiet(hop, on_event);
        }
        let min_tone = self.limits.min_tone;
        if let Some(open) = self.open.as_mut()
            && !open.reported
            && open.end - open.start >= min_tone
        {
            open.reported = true;
            on_event(DtmfEvent::Start {
                digit: open.digit,
                start: round_position(open.start),
            });
        }
    }

    /// A hop at least half covered by `digit`, whose tone measured `power`.
    fn on_tone(
        &mut self,
        hop: Hop<Digit>,
        digit: Digit,
        power: f64,
        before: Option<Hop<Digit>>,
        on_event: &mut impl FnMut(DtmfEvent),
    ) {
        let h = self.hop_len;
        let coverage = hop.coverage(power);
        let before_coverage = before
            .filter(|b| b.on().is_none())
            .map_or(0.0, |b| b.coverage(power));
        let start = start_edge(self.hop_start(hop.index), h, coverage, before_coverage);
        let end = end_edge(self.hop_start(hop.index) + h, h, coverage, 0.0);
        let continues = self.open.is_some_and(|open| {
            open.digit == digit
                && (open.last_on + 1 == hop.index || start - open.end < self.limits.min_pause)
        });
        if continues {
            if let Some(open) = self.open.as_mut() {
                open.end = end;
                open.last_on = hop.index;
                open.last_coverage = coverage;
                open.last_claim = power;
            }
            return;
        }
        if let Some(open) = self.open.take() {
            self.close(open, on_event);
        }
        self.open = Some(Open {
            digit,
            start,
            end,
            last_on: hop.index,
            last_coverage: coverage,
            last_claim: power,
            reported: false,
        });
    }

    /// A hop no digit covers half of.
    fn on_quiet(&mut self, hop: Hop<Digit>, on_event: &mut impl FnMut(DtmfEvent)) {
        let h = self.hop_len;
        let min_pause = self.limits.min_pause;
        // the earliest a tone heard from the next hop on could be placed is
        // half a hop before it: past that, no tone still to come can be an
        // interruption of this one
        let next_start = self.hop_start(hop.index + 1) - 0.5 * h;
        let Some(open) = self.open.as_mut() else {
            return;
        };
        if open.last_on + 1 == hop.index {
            let after = hop.coverage(open.last_claim);
            let last_end = position_f64(open.last_on + 1) * h;
            open.end = end_edge(last_end, h, open.last_coverage, after);
        }
        if next_start - open.end >= min_pause
            && let Some(open) = self.open.take()
        {
            self.close(open, on_event);
        }
    }

    fn close(&self, open: Open, on_event: &mut impl FnMut(DtmfEvent)) {
        let start = round_position(open.start);
        let end = round_position(open.end).max(start);
        if !open.reported {
            if open.end - open.start < self.limits.min_tone {
                return;
            }
            on_event(DtmfEvent::Start {
                digit: open.digit,
                start,
            });
        }
        on_event(DtmfEvent::End {
            digit: open.digit,
            start,
            end,
        });
    }
}

/// The strongest of the four filters from `first` on, by magnitude.
fn strongest(bank: &Analyzer, first: usize) -> Option<(usize, super::analysis::Reading)> {
    (0..4)
        .filter_map(|i| bank.reading(first + i).map(|r| (i, r)))
        .max_by(|a, b| a.1.magnitude.total_cmp(&b.1.magnitude))
}

#[cfg(test)]
mod tests {
    use super::{Digit, DtmfConfig, DtmfDetector, DtmfEvent, KeyPress};
    use crate::inband::SampleRate;
    use crate::inband::signals::{Rng, mix, pair, silence, sine, span, to_pcm, white};
    use crate::inband::{dbm0_to_peak, dbm0_to_power};

    const RATES: [SampleRate; 2] = [SampleRate::Hz8000, SampleRate::Hz16000];

    fn run(detector: &mut DtmfDetector, signal: &[f64]) -> Vec<DtmfEvent> {
        let mut events = Vec::new();
        detector.process(&to_pcm(signal), |e| events.push(e));
        detector.finish(|e| events.push(e));
        events
    }

    fn listen(rate: SampleRate, signal: &[f64]) -> Vec<DtmfEvent> {
        run(&mut DtmfDetector::new(rate), signal)
    }

    /// `lead` ms of silence, a digit of `ms`, 100 ms of silence.
    fn digit_signal(
        rate: SampleRate,
        digit: Digit,
        scale: (f64, f64),
        levels: (f64, f64),
        lead: f64,
        ms: f64,
    ) -> Vec<f64> {
        let (low, high) = digit.frequencies();
        let hz = rate.hz();
        let mut signal = silence(span(hz, lead));
        signal.extend(pair(
            (low * scale.0, levels.0),
            (high * scale.1, levels.1),
            hz,
            span(hz, ms),
        ));
        signal.extend(silence(span(hz, 100.0)));
        signal
    }

    fn presses(events: &[DtmfEvent]) -> Vec<KeyPress> {
        events
            .iter()
            .filter(|e| matches!(e, DtmfEvent::End { .. }))
            .map(DtmfEvent::key_press)
            .collect()
    }

    /// Exactly one start and one matching end, for `digit`.
    fn assert_one(events: &[DtmfEvent], digit: Digit, context: &str) -> KeyPress {
        assert_eq!(events.len(), 2, "{context}: {events:?}");
        assert!(
            matches!(events[0], DtmfEvent::Start { digit: d, .. } if d == digit),
            "{context}: {events:?}"
        );
        let press = events[1].key_press();
        assert_eq!(press.digit, digit, "{context}");
        assert_eq!(events[0].key_press().start, press.start, "{context}");
        press
    }

    #[test]
    fn every_digit_at_its_nominal_frequencies_is_heard_once_with_its_edges() {
        for rate in RATES {
            let per_ms = f64::from(rate.hz()) / 1_000.0;
            for digit in Digit::ALL {
                let signal = digit_signal(rate, digit, (1.0, 1.0), (-10.0, -10.0), 50.0, 60.0);
                let events = listen(rate, &signal);
                let press = assert_one(&events, digit, &format!("{rate:?} {digit:?}"));
                let start = f64::from(u32::try_from(press.start).unwrap()) / per_ms;
                let end = f64::from(u32::try_from(press.end).unwrap()) / per_ms;
                assert!(
                    (start - 50.0).abs() <= 1.0,
                    "{rate:?} {digit:?} start {start} ms"
                );
                assert!(
                    (end - 110.0).abs() <= 1.0,
                    "{rate:?} {digit:?} end {end} ms"
                );
            }
        }
    }

    #[test]
    fn a_deviation_of_one_and_a_half_percent_either_way_is_accepted() {
        for rate in RATES {
            for digit in Digit::ALL {
                for scale in [
                    (1.015, 1.015),
                    (1.015, 0.985),
                    (0.985, 1.015),
                    (0.985, 0.985),
                ] {
                    let signal = digit_signal(rate, digit, scale, (-10.0, -10.0), 50.0, 60.0);
                    assert_one(
                        &listen(rate, &signal),
                        digit,
                        &format!("{rate:?} {digit:?} {scale:?}"),
                    );
                }
            }
        }
    }

    #[test]
    fn a_deviation_of_one_and_a_half_percent_and_two_hertz_is_accepted() {
        // the CEPT column of Q.24 has a receiver operate within
        // ±(1.5 % + 2 Hz), a little wider than the North American ±1.5 %
        for rate in RATES {
            for digit in Digit::ALL {
                let (low, high) = digit.frequencies();
                for (low_sign, high_sign) in [(1.0, 1.0), (1.0, -1.0), (-1.0, 1.0), (-1.0, -1.0)] {
                    let scale = |f: f64, sign: f64| 1.0 + sign * (0.015 + 2.0 / f);
                    let scale = (scale(low, low_sign), scale(high, high_sign));
                    let signal = digit_signal(rate, digit, scale, (-10.0, -10.0), 50.0, 60.0);
                    assert_one(
                        &listen(rate, &signal),
                        digit,
                        &format!("{rate:?} {digit:?} {scale:?}"),
                    );
                }
            }
        }
    }

    #[test]
    fn the_loudest_pair_the_samples_carry_is_accepted_with_either_twist() {
        // two tones at -3 dBm0 peak just under full scale together; louder,
        // and the sum clips
        for rate in RATES {
            for digit in Digit::ALL {
                for levels in [(-3.0, -3.0), (-7.0, -3.0), (-3.0, -11.0)] {
                    let signal = digit_signal(rate, digit, (1.0, 1.0), levels, 50.0, 60.0);
                    assert_one(
                        &listen(rate, &signal),
                        digit,
                        &format!("{rate:?} {digit:?} {levels:?}"),
                    );
                }
            }
        }
    }

    #[test]
    fn a_deviation_of_three_and_a_half_percent_on_either_tone_is_refused() {
        for rate in RATES {
            for digit in Digit::ALL {
                for scale in [(1.035, 1.0), (0.965, 1.0), (1.0, 1.035), (1.0, 0.965)] {
                    let signal = digit_signal(rate, digit, scale, (-10.0, -10.0), 50.0, 60.0);
                    let events = listen(rate, &signal);
                    assert!(
                        events.is_empty(),
                        "{rate:?} {digit:?} {scale:?}: {events:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn twist_is_accepted_inside_both_limits_and_refused_past_either() {
        for rate in RATES {
            for digit in Digit::ALL {
                for (twist, accepted) in [(3.5, true), (4.5, false), (-7.5, true), (-8.5, false)] {
                    let levels = (-14.0, -14.0 + twist);
                    let signal = digit_signal(rate, digit, (1.0, 1.0), levels, 50.0, 60.0);
                    let events = listen(rate, &signal);
                    let context = format!("{rate:?} {digit:?} twist {twist}");
                    if accepted {
                        assert_one(&events, digit, &context);
                    } else {
                        assert!(events.is_empty(), "{context}: {events:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn forty_milliseconds_is_a_digit_at_every_alignment_and_twenty_three_is_not() {
        for rate in RATES {
            let hz = rate.hz();
            let per_ms = f64::from(hz) / 1_000.0;
            // every offset within a hop, in steps finer than a millisecond
            for offset in 0..10 {
                let lead = 50.0 + f64::from(offset) * 0.6;
                for digit in [Digit::One, Digit::Five, Digit::Nine, Digit::D] {
                    let signal = digit_signal(rate, digit, (1.0, 1.0), (-10.0, -10.0), lead, 40.0);
                    let press = assert_one(
                        &listen(rate, &signal),
                        digit,
                        &format!("{rate:?} 40 ms at {lead}"),
                    );
                    let measured =
                        f64::from(u32::try_from(press.end - press.start).unwrap()) / per_ms;
                    assert!(
                        (measured - 40.0).abs() <= 1.5,
                        "{rate:?} measured {measured} ms"
                    );

                    let signal = digit_signal(rate, digit, (1.0, 1.0), (-10.0, -10.0), lead, 23.0);
                    let events = listen(rate, &signal);
                    assert!(events.is_empty(), "{rate:?} 23 ms at {lead}: {events:?}");
                }
            }
        }
    }

    fn two_bursts(rate: SampleRate, first: Digit, second: Digit, gap_ms: f64) -> Vec<f64> {
        let hz = rate.hz();
        let mut signal = digit_signal(rate, first, (1.0, 1.0), (-10.0, -10.0), 50.0, 60.0);
        signal.truncate(span(hz, 110.0));
        signal.extend(silence(span(hz, gap_ms)));
        let (low, high) = second.frequencies();
        signal.extend(pair((low, -10.0), (high, -10.0), hz, span(hz, 60.0)));
        signal.extend(silence(span(hz, 100.0)));
        signal
    }

    #[test]
    fn a_forty_millisecond_pause_separates_two_presses_of_one_key() {
        for rate in RATES {
            let events = listen(rate, &two_bursts(rate, Digit::Seven, Digit::Seven, 40.0));
            let got = presses(&events);
            assert_eq!(got.len(), 2, "{rate:?}: {events:?}");
            assert!(got.iter().all(|p| p.digit == Digit::Seven));
        }
    }

    #[test]
    fn a_ten_millisecond_interruption_does_not_split_a_digit() {
        for rate in RATES {
            let per_ms = f64::from(rate.hz()) / 1_000.0;
            let events = listen(rate, &two_bursts(rate, Digit::Seven, Digit::Seven, 10.0));
            let press = assert_one(&events, Digit::Seven, &format!("{rate:?}"));
            let length = f64::from(u32::try_from(press.end - press.start).unwrap()) / per_ms;
            assert!((length - 130.0).abs() <= 2.0, "{rate:?}: {length} ms");
        }
    }

    #[test]
    fn two_different_keys_are_two_presses_whatever_the_pause() {
        for rate in RATES {
            for gap in [40.0, 10.0] {
                let events = listen(rate, &two_bursts(rate, Digit::Three, Digit::Hash, gap));
                let got: Vec<Digit> = presses(&events).iter().map(|p| p.digit).collect();
                assert_eq!(
                    got,
                    [Digit::Three, Digit::Hash],
                    "{rate:?} gap {gap}: {events:?}"
                );
            }
        }
    }

    #[test]
    fn a_digit_just_above_the_level_floor_is_heard_and_just_below_it_is_not() {
        for rate in RATES {
            for digit in Digit::ALL {
                let quiet = digit_signal(rate, digit, (1.0, 1.0), (-29.0, -29.0), 50.0, 60.0);
                assert_one(
                    &listen(rate, &quiet),
                    digit,
                    &format!("{rate:?} {digit:?} -29"),
                );
                let quieter = digit_signal(rate, digit, (1.0, 1.0), (-31.0, -31.0), 50.0, 60.0);
                assert!(listen(rate, &quieter).is_empty(), "{rate:?} {digit:?} -31");
                // one tone loud enough that the pair clears the floor
                // together, and the other alone above or below it
                let lopsided = digit_signal(rate, digit, (1.0, 1.0), (-23.0, -29.0), 50.0, 60.0);
                assert_one(
                    &listen(rate, &lopsided),
                    digit,
                    &format!("{rate:?} {digit:?} -23/-29"),
                );
                let lopsided = digit_signal(rate, digit, (1.0, 1.0), (-24.0, -31.0), 50.0, 60.0);
                assert!(
                    listen(rate, &lopsided).is_empty(),
                    "{rate:?} {digit:?} -24/-31"
                );
            }
        }
    }

    /// A digit at −10 dBm0 per tone with a steady interferer whose power
    /// sits `snr` dB under the two tones together.
    fn with_interferer(rate: SampleRate, digit: Digit, frequency: f64, snr: f64) -> Vec<f64> {
        let hz = rate.hz();
        let mut signal = digit_signal(rate, digit, (1.0, 1.0), (-10.0, -10.0), 50.0, 80.0);
        let tones = 2.0 * dbm0_to_power(-10.0);
        let amplitude = (2.0 * tones / 10f64.powf(snr / 10.0)).sqrt();
        let interferer = sine(frequency, amplitude, 0.0, hz, signal.len());
        mix(&mut signal, &interferer);
        signal
    }

    #[test]
    fn a_third_tone_is_tolerated_above_the_signal_to_noise_floor_and_not_below_it() {
        for rate in RATES {
            for digit in Digit::ALL {
                let clean = with_interferer(rate, digit, 2_200.0, 12.0);
                assert_one(
                    &listen(rate, &clean),
                    digit,
                    &format!("{rate:?} {digit:?} 12 dB"),
                );
                let dirty = with_interferer(rate, digit, 2_200.0, 8.0);
                assert!(listen(rate, &dirty).is_empty(), "{rate:?} {digit:?} 8 dB");
            }
        }
    }

    #[test]
    fn a_second_harmonic_beside_the_column_tone_is_measured_through_its_leak() {
        // 2 x 697 Hz is 58 Hz from 1336 and 2 x 770 is 63 Hz from 1477: the
        // column tone leaks into the harmonic's filter and the harmonic into
        // the column's, and a harmonic 2.5 dB over the limit is refused only
        // once what the two filters share is given back to it
        for rate in RATES {
            let hz = rate.hz();
            for digit in [Digit::Two, Digit::Six] {
                let (low, _) = digit.frequencies();
                for (relative, accepted) in [(-12.5, false), (-17.0, true)] {
                    let mut signal =
                        digit_signal(rate, digit, (1.0, 1.0), (-10.0, -10.0), 50.0, 60.0);
                    let amplitude = dbm0_to_peak(-10.0 + relative);
                    let harmonic = sine(2.0 * low, amplitude, 0.7, hz, signal.len());
                    mix(&mut signal, &harmonic);
                    let events = listen(rate, &signal);
                    let context = format!("{rate:?} {digit:?} at {relative} dB");
                    if accepted {
                        assert_one(&events, digit, &context);
                    } else {
                        assert!(events.is_empty(), "{context}: {events:?}");
                    }
                }
            }
        }
    }

    #[test]
    fn a_strong_second_harmonic_on_either_tone_is_refused_and_a_weak_one_is_not() {
        for rate in RATES {
            let hz = rate.hz();
            for digit in Digit::ALL {
                let (low, high) = digit.frequencies();
                for base in [low, high] {
                    for (relative, accepted) in [(-25.0, true), (-10.0, false)] {
                        let mut signal =
                            digit_signal(rate, digit, (1.0, 1.0), (-10.0, -10.0), 50.0, 60.0);
                        let amplitude = dbm0_to_peak(-10.0 + relative);
                        let harmonic = sine(2.0 * base, amplitude, 0.7, hz, signal.len());
                        mix(&mut signal, &harmonic);
                        let events = listen(rate, &signal);
                        let context = format!("{rate:?} {digit:?} 2 x {base} at {relative} dB");
                        if accepted {
                            assert_one(&events, digit, &context);
                        } else {
                            assert!(events.is_empty(), "{context}: {events:?}");
                        }
                    }
                }
            }
        }
    }

    /// Both of `digit`'s tones gliding up through their nominal frequencies
    /// together, each inside ±2.5 % of it for `in_band_ms`, from 15 % below
    /// to 15 % above, between stretches of silence.
    fn glide(rate: SampleRate, digit: Digit, in_band_ms: f64) -> Vec<f64> {
        let hz = rate.hz();
        let fs = f64::from(hz);
        // the band is 5 % of the frequency wide; crossing it in `in_band_ms`
        // takes this fraction of the frequency per second
        let speed = 0.05 / (in_band_ms / 1_000.0);
        let len = span(hz, 0.3 / speed * 1_000.0);
        let (low, high) = digit.frequencies();
        let mut signal = silence(span(hz, 50.0));
        let mut phases = (0.4, 1.3);
        let amplitude = dbm0_to_peak(-10.0);
        for n in 0..len {
            let t = f64::from(u32::try_from(n).unwrap()) / f64::from(u32::try_from(len).unwrap());
            let scale = 0.85 + 0.3 * t;
            phases.0 += 2.0 * std::f64::consts::PI * low * scale / fs;
            phases.1 += 2.0 * std::f64::consts::PI * high * scale / fs;
            signal.push(amplitude * (phases.0.sin() + phases.1.sin()));
        }
        signal.extend(silence(span(hz, 100.0)));
        signal
    }

    #[test]
    fn a_pair_that_glides_through_its_band_faster_than_a_digit_lasts_is_not_one() {
        for rate in RATES {
            for digit in Digit::ALL {
                // inside the band for 20 ms, under the 23 ms Q.24 refuses
                let events = listen(rate, &glide(rate, digit, 20.0));
                assert!(events.is_empty(), "{rate:?} {digit:?}: {events:?}");
            }
        }
    }

    #[test]
    fn every_digit_is_heard_through_white_noise_fifteen_db_down() {
        let mut rng = Rng::new(0x5EED_D1A1);
        for rate in RATES {
            for digit in Digit::ALL {
                let mut signal = digit_signal(rate, digit, (1.0, 1.0), (-10.0, -10.0), 50.0, 60.0);
                // two tones at -10 dBm0 are -7 dBm0 together
                let noise = white(&mut rng, -22.0, signal.len());
                mix(&mut signal, &noise);
                assert_one(
                    &listen(rate, &signal),
                    digit,
                    &format!("{rate:?} {digit:?}"),
                );
            }
        }
    }

    #[test]
    fn how_the_audio_is_sliced_changes_nothing() {
        let rate = SampleRate::Hz8000;
        let mut signal = Vec::new();
        for digit in Digit::ALL {
            signal.extend(digit_signal(
                rate,
                digit,
                (1.0, 1.0),
                (-12.0, -10.0),
                30.0,
                50.0,
            ));
        }
        let pcm = to_pcm(&signal);
        let whole = listen(rate, &signal);
        assert_eq!(presses(&whole).len(), 16);
        let mut rng = Rng::new(77);
        let mut detector = DtmfDetector::new(rate);
        let mut sliced = Vec::new();
        let mut rest = pcm.as_slice();
        while !rest.is_empty() {
            let take = usize::try_from(rng.next_u64() % 300)
                .unwrap()
                .min(rest.len());
            let (chunk, tail) = rest.split_at(take);
            detector.process(chunk, |e| sliced.push(e));
            rest = tail;
        }
        detector.finish(|e| sliced.push(e));
        assert_eq!(whole, sliced);
    }

    #[test]
    fn a_digit_still_sounding_when_the_stream_ends_is_closed_by_finish() {
        let rate = SampleRate::Hz8000;
        let mut detector = DtmfDetector::new(rate);
        let (low, high) = Digit::Eight.frequencies();
        let mut signal = silence(400);
        signal.extend(pair((low, -10.0), (high, -10.0), 8_000, 800));
        let mut events = Vec::new();
        detector.process(&to_pcm(&signal), |e| events.push(e));
        assert_eq!(events.len(), 1, "{events:?}");
        detector.finish(|e| events.push(e));
        let press = assert_one(&events, Digit::Eight, "finish");
        assert!(press.start.abs_diff(400) <= 8);
        assert!(press.end.abs_diff(1_200) <= 8);
    }

    #[test]
    fn reset_forgets_a_digit_in_progress() {
        let rate = SampleRate::Hz8000;
        let mut detector = DtmfDetector::new(rate);
        let (low, high) = Digit::Eight.frequencies();
        let signal = pair((low, -10.0), (high, -10.0), 8_000, 800);
        let mut events = Vec::new();
        detector.process(&to_pcm(&signal), |e| events.push(e));
        assert_eq!(events.len(), 1);
        detector.reset();
        detector.process(&to_pcm(&silence(800)), |e| events.push(e));
        detector.finish(|e| events.push(e));
        assert_eq!(events.len(), 1, "no end for a digit reset away: {events:?}");
    }

    #[test]
    fn a_tighter_configuration_is_honoured() {
        let rate = SampleRate::Hz8000;
        let config = DtmfConfig {
            min_tone_ms: 70,
            ..DtmfConfig::default()
        };
        let signal = digit_signal(rate, Digit::Two, (1.0, 1.0), (-10.0, -10.0), 50.0, 60.0);
        assert!(run(&mut DtmfDetector::with_config(rate, config), &signal).is_empty());
        let signal = digit_signal(rate, Digit::Two, (1.0, 1.0), (-10.0, -10.0), 50.0, 80.0);
        assert_eq!(
            presses(&run(&mut DtmfDetector::with_config(rate, config), &signal)).len(),
            1
        );
    }

    #[test]
    fn keys_name_their_characters_codes_and_frequencies() {
        for (code, digit) in Digit::ALL.iter().enumerate() {
            assert_eq!(usize::from(digit.event_code()), code);
            assert_eq!(Digit::from_event_code(digit.event_code()), Some(*digit));
            assert_eq!(Digit::from_char(digit.to_char()), Some(*digit));
        }
        assert_eq!(Digit::from_event_code(16), None);
        assert_eq!(Digit::from_char('x'), None);
        assert_eq!(Digit::from_char('d'), Some(Digit::D));
        assert_eq!(Digit::One.frequencies(), (697.0, 1_209.0));
        assert_eq!(Digit::Zero.frequencies(), (941.0, 1_336.0));
        assert_eq!(Digit::Hash.frequencies(), (941.0, 1_477.0));
        assert_eq!(Digit::D.frequencies(), (941.0, 1_633.0));
    }

    #[test]
    fn a_tone_and_an_event_for_one_key_are_one_press_and_two_keys_are_not() {
        let heard = KeyPress {
            digit: Digit::Five,
            start: 8_000,
            end: 8_800,
        };
        let event = KeyPress::from_telephone_event(5, 8_120, 800).unwrap();
        assert!(heard.is_same_press(&event, 0));
        assert!(event.is_same_press(&heard, 0));
        let later = KeyPress::from_telephone_event(5, 9_200, 800).unwrap();
        assert!(!heard.is_same_press(&later, 0));
        assert!(
            heard.is_same_press(&later, 480),
            "a 400-sample gap inside the tolerance"
        );
        let other = KeyPress::from_telephone_event(6, 8_120, 800).unwrap();
        assert!(!heard.is_same_press(&other, 10_000));
        assert_eq!(KeyPress::from_telephone_event(16, 0, 0), None);
        let start = DtmfEvent::Start {
            digit: Digit::Five,
            start: 8_000,
        };
        assert!(start.key_press().is_same_press(&event, 160));
    }

    #[test]
    fn arbitrary_audio_never_panics() {
        let mut rng = Rng::new(0xFACE);
        for rate in RATES {
            let mut detector = DtmfDetector::new(rate);
            for _ in 0..200 {
                let len = usize::try_from(rng.next_u64() % 500).unwrap();
                let pattern = rng.next_u64() % 4;
                let chunk: Vec<i16> = (0..len)
                    .map(|i| match pattern {
                        0 => 0,
                        1 if i % 2 == 0 => i16::MAX,
                        1 => i16::MIN,
                        2 => i16::MAX,
                        _ => i16::try_from(i64::try_from(rng.next_u64() >> 48).unwrap() - 32_768)
                            .unwrap(),
                    })
                    .collect();
                detector.process(&chunk, |_| {});
            }
            detector.finish(|_| {});
        }
    }
}
