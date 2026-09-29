// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Call-progress tones: what a network plays to a caller while it connects
//! a call, or instead of connecting it.
//!
//! The tones are data, not code. A [`ToneSpec`] names a tone, its
//! frequencies, and its cadence — a repeating list of [`Burst`]s of tone and
//! silence, or [`Cadence::Continuous`] — and a [`Region`] is a table of
//! them, and drives [`ToneGenerator`](super::generate::ToneGenerator).
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
//! variants falls inside E.180's tolerances.

/// What a call-progress tone means.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProgressTone {
    /// The exchange is ready for digits.
    Dial,
    /// The far end is being alerted: audible ringing, or ringback.
    Ringback,
    /// The far end is busy.
    Busy,
    /// The network is: congestion, or reorder in North America.
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
