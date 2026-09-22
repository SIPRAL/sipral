// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Segmental SNR and splice continuity for the tone the lab's own dialplan
//! plays back — the audio quality gate `scripts/lab.sh netem` runs on top of
//! `Flow::Call`.
//!
//! # What comes back is not an echo, and that turns out to be better
//!
//! The first design compared what came back with what this harness itself
//! sent. It does not fit what the lab actually does: extension 9000 does not
//! echo — `interop/asterisk/extensions.conf`'s own 9002 plays
//! `Playtones(350+440/1200,0/600)`, and `interop/freeswitch/lab.xml`'s 9002
//! plays `tone_stream://%(1200,600,350,440)`, both a fixed 350 Hz + 440 Hz
//! tone cadenced 1200 ms on and 600 ms off — the same cadence this harness's
//! own `audio::SPURT`/`audio::PAUSE` use, on purpose. FreeSWITCH's own
//! file says why there is no echo: one was tried, and did not survive its
//! loopback channel — eight packets back out of a hundred and two, worse than
//! the impairment this gate exists to measure.
//!
//! That turns out to be the better foundation anyway. An echo compares the
//! network against a copy of what this end sent moments earlier — itself
//! something the jitter buffer, the codec and this harness's own capture loop
//! have already touched. The lab's dialplan is a **known, fixed signal**,
//! declared in files this repository owns and never opened at the far end's
//! own source, so any deviation this module finds is unambiguously the
//! path's doing: loss, jitter, concealment, a codec's own quantisation —
//! never a discrepancy in what this end happened to send.
//!
//! # Fitting the tone, once per run
//!
//! Two sinusoids at fixed but a priori unknown amplitude and phase — the far
//! end's own tone generator does not promise either — are four unknowns:
//! `a1*cos(w1*n) + b1*sin(w1*n) + a2*cos(w2*n) + b2*sin(w2*n)`, `w1`/`w2` the
//! two frequencies in radians per sample at the call's own rate. [`solve4`]
//! recovers the four by ordinary least squares — plain Gaussian elimination
//! on the resulting four-by-four system, nothing borrowed from any
//! signal-processing library — over [`seed_window`]'s own count of samples:
//! exactly one common period of both frequencies, since 350 Hz and 440 Hz
//! share a ten-hertz divisor. That is what makes the fit accurate rather
//! than merely possible: over any other window length the four basis
//! functions overlap a little, and the least-squares solution absorbs that
//! overlap as residual error, which a frame or two later can itself read as
//! a splice. Over an exact common period they are genuinely orthogonal, the
//! same reason a Fourier series is taken over one, and the residual very
//! nearly vanishes. A run that ends before a full window has arrived — too
//! short a spurt, too much loss right at its start — is not fit at all, and
//! nothing in it is scored: [`State::Seeding`] holds what has arrived so far
//! and the accumulating fit alongside it, both discarded together the moment
//! [`classify`] says the run is over.
//!
//! Fitting **once, at the start of a run**, rather than fresh on every
//! frame, is the load-bearing choice regardless of the window it is taken
//! over: a fit done independently per frame always finds *some* pair of
//! amplitudes that minimises its own error, corrupted frame or not, and so
//! never disagrees with one. [`Run::n`] instead advances the fitted
//! reference one sample at a time for the rest of the run — through
//! concealed frames as much as real ones, because the far end's own
//! generator did not stop just because a packet went missing — so a frame
//! that departs from the continuation the run actually started as is exactly
//! what segmental SNR and the splice check are here to catch. Every frame
//! collected while the fit is still being seeded is scored the same way, in
//! order, the moment the fit completes — [`finish_seeding`] — so a run's
//! first several frames are not exempted from either check merely because
//! the fit they are judged against was not ready until they had already
//! arrived.
//!
//! A run is this end's own [`audio::is_audible`] saying so: it starts at a
//! [`sipral::Playback::Packet`] frame loud enough to be the tone, continues
//! through further such frames and through [`sipral::Playback::Concealed`]
//! ones, and ends the moment a frame is not loud enough or reports
//! [`sipral::Playback::ComfortNoise`] or [`sipral::Playback::Silence`]
//! instead. Nothing here reads the far end's own cadence; it reads what this
//! end's ear already calls the tone, the same test [`audio::Heard::audible`]
//! is counted by.
//!
//! # Segmental SNR
//!
//! Computed per played frame, on [`sipral::Playback::Packet`] frames only —
//! "the frames that arrived" — as ten times the base-ten logarithm of the
//! fitted reference's own energy over the squared error against it, clamped
//! to [`SEGMENT_DB_FLOOR`]..[`SEGMENT_DB_CEIL`] the way segmental SNR
//! ordinarily is, so one near-silent frame's huge or undefined ratio cannot
//! swing the call's average. [`Report::mean_seg_snr_db`] is the plain mean of
//! every frame scored this way.
//!
//! Concealed frames are excluded from the sum by design: the concealer never
//! claimed to reproduce the lab's own tone, only to keep the ear from
//! noticing the gap, so scoring its output against the tone would be judging
//! it on a claim it never made. What it is judged on is continuity, below.
//!
//! # Splice continuity
//!
//! At the first sample where a run's kind changes — real audio giving way to
//! concealment, or concealment giving way to real audio again — this compares
//! the jump actually played (this sample minus the last one) against the
//! steepest step the fitted tone takes anywhere in its cycle
//! ([`steepest_step`]), plus [`CLICK_FLOOR`] and [`CLICK_MARGIN_FRACTION`] of
//! it again. Not against the reference's own step at that instant: the
//! concealer's extension and its cross-fade are not phase-locked to either
//! sinusoid, so around a splice the audio played can be a quarter of a cycle
//! from the reference, steep exactly where the reference is flat, and a
//! smooth resume there read as a click on the first lab runs of this gate.
//! A jump no larger than the tone's own slope is not a discontinuity by any
//! reading, wherever in the cycle it falls; what clears the threshold is the
//! played signal leaping by something of the order of its own amplitude,
//! which is what "far above the signal's own slope" means in practice.

use sipral::Playback;

use crate::audio;

/// The lower of the two frequencies the lab's own dialplan plays —
/// `interop/asterisk/extensions.conf`'s `Playtones(350+440/...)` and
/// `interop/freeswitch/lab.xml`'s `tone_stream://%(...,350,440)` agree on
/// both.
const FREQ_LOW: f64 = 350.0;

/// The higher of the two.
const FREQ_HIGH: f64 = 440.0;

/// The lowest a single frame's segmental SNR is allowed to pull the call's
/// average down to. A frame this bad is real evidence of a bad frame; letting
/// it go lower would let one frame's arithmetic (a noise sum near zero from
/// an accidental near-perfect match, or a signal sum near zero because the
/// run's fit landed on a near-silent stretch) dominate every other frame
/// scored.
const SEGMENT_DB_FLOOR: f64 = -10.0;

/// The highest a single frame's segmental SNR is allowed to read. The ceiling
/// exists so a frame whose noise sum rounds to zero cannot report an
/// unbounded ratio.
const SEGMENT_DB_CEIL: f64 = 60.0;

/// The smallest energy (signal or noise) a frame is treated as having, so a
/// silent stretch cannot divide by zero or take the logarithm of it.
const MIN_ENERGY: f64 = 1.0;

/// The flat amount added on top of the tone's steepest step to make the
/// click threshold — what a splice's fit residual, quantisation noise and
/// the cross-fade's own ramp spend beyond the tone's slope. Calibrated on the
/// lab VM — see `docs/11-testing.md` for the measured spread this was set
/// above.
const CLICK_FLOOR: f64 = 900.0;

/// How far past the tone's steepest step ([`steepest_step`]) a jump may land,
/// as a fraction of that step, before it counts as a click. Kept separate
/// from [`CLICK_FLOOR`] because the two answer different questions: the floor
/// is what a splice costs even on a quiet tone, the margin is how much steeper
/// than any sample of the tone itself a splice may be on a loud one. The
/// threshold, `steepest + CLICK_FLOOR + CLICK_MARGIN_FRACTION * steepest`, is
/// never less than the steepest step the tone takes anywhere — a jump no
/// larger than the tone's own slope is not a discontinuity by any reading —
/// and a real click, the played signal leaping by something of the order of
/// its own amplitude, clears it.
const CLICK_MARGIN_FRACTION: f64 = 0.6;

/// The least a call's segmental SNR may average and still pass. Calibrated on
/// the lab VM: see `docs/11-testing.md` for the measured numbers a clean run
/// and each netem profile produced, and the margin kept below the worst of
/// them.
pub(crate) const MIN_SEGMENTAL_SNR_DB: f64 = 10.0;

/// How many samples a run's fit is taken over, at `rate` — see the module
/// doc for why this particular count rather than one frame's worth.
fn seed_window(rate: u32) -> usize {
    usize::try_from(rate / 10).unwrap_or(800)
}

/// One side of a run: real audio continuing it, or concealment.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Packet,
    Concealed,
}

/// What a played frame is classified as, from this end's own reading of it —
/// never from what the far end was asked to send, which is exactly what a
/// lossy path is free to not deliver.
enum Classification {
    /// Continues a run, scored for segmental SNR once the run has a fit.
    Packet,
    /// Continues a run, scored only for the splice at either edge of it.
    Concealed,
    /// Ends whatever run was open: nothing here reads as the tone.
    Quiet,
}

fn classify(outcome: Playback, samples: &[i16]) -> Classification {
    match outcome {
        Playback::Concealed => Classification::Concealed,
        Playback::Packet if audio::is_audible(samples) => Classification::Packet,
        // a quiet `Packet` is silence the far end genuinely sent (the pause
        // between spurts), and `ComfortNoise`/`Silence` and anything
        // `Playback`'s own `#[non_exhaustive]` adds later are treated the
        // same way: nothing here is the tone, so no run continues through it
        _ => Classification::Quiet,
    }
}

/// A run with an established fit, mid-flight: the two sinusoids' fitted
/// coefficients, how far into the run the reference clock has run, and where
/// the reference and the actual signal stood at the end of the last frame
/// scored, for the splice check at the start of the next one.
struct Run {
    /// Samples since the run began — the argument to the fitted reference's
    /// own trigonometric functions, advanced by every sample of every frame
    /// the run has taken, whether or not that frame was scored.
    n: u64,
    /// `[a1, b1, a2, b2]` in `a1*cos(w1*n) + b1*sin(w1*n) + a2*cos(w2*n) +
    /// b2*sin(w2*n)`.
    coefficients: [f64; 4],
    last_sample: f64,
    last_kind: Kind,
    /// Whether a frame has been scored yet. The run's first frame seeds
    /// `last_sample` rather than being compared against it — there is
    /// nothing yet for it to have jumped from.
    seeded: bool,
}

impl Run {
    fn new(coefficients: [f64; 4]) -> Self {
        Self {
            n: 0,
            coefficients,
            last_sample: 0.0,
            last_kind: Kind::Packet,
            seeded: false,
        }
    }
}

/// One call's tally, separate from [`State`] so a frame taken mid-run can
/// borrow this and the run it is scored into at once.
#[derive(Default)]
struct Counters {
    segment_db_sum: f64,
    segment_count: u32,
    concealed_frames: u32,
    edges_checked: u32,
    clicks: u32,
}

/// Where a call's gate stands: nothing in progress, a run whose fit is still
/// being accumulated, or one already scoring frames against it.
enum State {
    Empty,
    /// A candidate run that has not yet collected [`seed_window`]'s count of
    /// samples: every frame taken so far, kept so [`finish_seeding`] can
    /// score each of them once the fit is ready, and the Gram matrix and
    /// right-hand side accumulated from them, so finishing the fit is a
    /// [`solve4`] rather than a second pass over every sample.
    Seeding {
        frames: Vec<(Kind, Vec<i16>)>,
        gram: [[f64; 4]; 4],
        rhs: [f64; 4],
        collected: usize,
    },
    Running(Run),
}

/// The four basis values — `cos`/`sin` of each frequency — at sample `k` of
/// a fit window.
fn basis(k: usize, w_low: f64, w_high: f64) -> [f64; 4] {
    #[allow(clippy::cast_precision_loss)]
    let k = k as f64;
    [
        (w_low * k).cos(),
        (w_low * k).sin(),
        (w_high * k).cos(),
        (w_high * k).sin(),
    ]
}

/// Folds `samples` into a Gram matrix and right-hand side being accumulated
/// for [`solve4`], `base_k` samples into the window already.
fn accumulate(
    gram: &mut [[f64; 4]; 4],
    rhs: &mut [f64; 4],
    base_k: usize,
    samples: &[i16],
    w_low: f64,
    w_high: f64,
) {
    for (offset, &actual) in samples.iter().enumerate() {
        let phi = basis(base_k + offset, w_low, w_high);
        let observed = f64::from(actual);
        for row in 0..4 {
            let phi_row = phi.get(row).copied().unwrap_or(0.0);
            if let Some(cell) = rhs.get_mut(row) {
                *cell += phi_row * observed;
            }
            if let Some(gram_row) = gram.get_mut(row) {
                for (col, &phi_col) in phi.iter().enumerate() {
                    if let Some(cell) = gram_row.get_mut(col) {
                        *cell += phi_row * phi_col;
                    }
                }
            }
        }
    }
}

/// Solves the four-by-four system `m * x = v` for `x`, by Gaussian
/// elimination with partial pivoting — plain linear algebra, not a library's.
/// `None` when `m` is singular to working precision: a window with no
/// measurable energy at either frequency, which [`classify`] having called
/// every frame in it audible makes exceedingly unlikely.
fn solve4(mut m: [[f64; 4]; 4], mut v: [f64; 4]) -> Option<[f64; 4]> {
    let cell = |grid: &[[f64; 4]; 4], row: usize, col: usize| {
        grid.get(row)
            .and_then(|line| line.get(col))
            .copied()
            .unwrap_or(0.0)
    };
    for col in 0..4 {
        let mut pivot_row = col;
        let mut pivot_value = cell(&m, col, col).abs();
        for (row, candidate) in m.iter().enumerate().skip(col + 1) {
            let value = candidate.get(col).copied().unwrap_or(0.0).abs();
            if value > pivot_value {
                pivot_value = value;
                pivot_row = row;
            }
        }
        if pivot_value < 1e-6 {
            return None;
        }
        m.swap(pivot_row, col);
        v.swap(pivot_row, col);
        let pivot = cell(&m, col, col);
        for row in (col + 1)..4 {
            let factor = cell(&m, row, col) / pivot;
            for k in col..4 {
                let subtrahend = factor * cell(&m, col, k);
                if let Some(target) = m.get_mut(row).and_then(|line| line.get_mut(k)) {
                    *target -= subtrahend;
                }
            }
            let subtrahend = factor * v.get(col).copied().unwrap_or(0.0);
            if let Some(target) = v.get_mut(row) {
                *target -= subtrahend;
            }
        }
    }
    let mut x = [0.0_f64; 4];
    for row in (0..4).rev() {
        let mut sum = v.get(row).copied().unwrap_or(0.0);
        for (k, &solved) in x.iter().enumerate().skip(row + 1) {
            sum -= cell(&m, row, k) * solved;
        }
        let quotient = sum / cell(&m, row, row);
        if let Some(target) = x.get_mut(row) {
            *target = quotient;
        }
    }
    Some(x)
}

/// The fitted reference's value `n` samples into the run it was fitted for.
fn reference_at(coefficients: [f64; 4], n: u64, w_low: f64, w_high: f64) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    let n = n as f64;
    coefficients[0].mul_add((w_low * n).cos(), coefficients[1] * (w_low * n).sin())
        + coefficients[2].mul_add((w_high * n).cos(), coefficients[3] * (w_high * n).sin())
}

/// The largest step, sample to sample, the fitted tone takes anywhere in its
/// cycle: `2·A·sin(ω/2)` for each of its two sinusoids, summed. A single
/// sinusoid of amplitude `A` never moves by more than that between two
/// samples, and two of them together never by more than the sum.
///
/// This, and not the reference's own step at the splice, is the slope a
/// splice is measured against. Concealment is not phase-locked to the tone,
/// so by the time a gap ends the audio being played, the concealer's
/// extension and then the cross-fade out of it, can be a quarter of a cycle
/// away from the reference: steep where the reference happens to sit at a
/// peak. Measured against the reference's step there, a perfectly smooth
/// resume read as a click; the first lab runs of this gate failed four
/// calls in ten on `mobile` that way, every one of them a continuation
/// whose next few steps were as large as the one flagged.
fn steepest_step(coefficients: [f64; 4], w_low: f64, w_high: f64) -> f64 {
    let low = coefficients[0].hypot(coefficients[1]);
    let high = coefficients[2].hypot(coefficients[3]);
    2.0 * low * (w_low / 2.0).sin() + 2.0 * high * (w_high / 2.0).sin()
}

/// Segmental SNR is the mean of the base-ten logarithm of the reference's own
/// energy over the squared error against it, clamped per frame — see the
/// module doc for why the clamp exists.
fn segmental_db(signal: f64, noise: f64) -> f64 {
    let ratio = signal.max(MIN_ENERGY) / noise.max(MIN_ENERGY);
    (10.0 * ratio.log10()).clamp(SEGMENT_DB_FLOOR, SEGMENT_DB_CEIL)
}

/// Takes one frame into `run`: the splice check if its kind differs from the
/// last frame scored, then segmental SNR if `scorable`, advancing `run.n` by
/// `samples.len()` either way. Free rather than a method on [`Gate`] so a
/// caller already holding `&mut` to the [`Run`] inside [`State::Running`] can
/// still reach the counters beside it — see [`State`]'s own doc.
fn score(
    run: &mut Run,
    counters: &mut Counters,
    kind: Kind,
    samples: &[i16],
    w_low: f64,
    w_high: f64,
    scorable: bool,
) {
    if let Some(&first) = samples.first()
        && run.seeded
        && run.last_kind != kind
    {
        let observed = (f64::from(first) - run.last_sample).abs();
        let steepest = steepest_step(run.coefficients, w_low, w_high);
        counters.edges_checked = counters.edges_checked.saturating_add(1);
        let threshold = steepest + CLICK_FLOOR + CLICK_MARGIN_FRACTION * steepest;
        if observed > threshold {
            counters.clicks = counters.clicks.saturating_add(1);
        }
    }

    let mut frame_signal = 0.0_f64;
    let mut frame_noise = 0.0_f64;
    for &actual in samples {
        let reference = reference_at(run.coefficients, run.n, w_low, w_high);
        let actual_value = f64::from(actual);
        if scorable {
            let diff = actual_value - reference;
            frame_signal += reference * reference;
            frame_noise += diff * diff;
        }
        run.last_sample = actual_value;
        run.n += 1;
    }
    run.last_kind = kind;
    run.seeded = true;

    if scorable {
        counters.segment_db_sum += segmental_db(frame_signal, frame_noise);
        counters.segment_count = counters.segment_count.saturating_add(1);
    }
}

/// A window's worth of frames has just arrived: solve for the fit and score
/// every frame collected while it was being seeded, in order, exactly as
/// [`score`] would have scored each in real time. `State::Empty` when the
/// window carried no measurable energy at either frequency — see
/// [`solve4`]'s own doc for when that is.
fn finish_seeding(
    frames: &[(Kind, Vec<i16>)],
    gram: [[f64; 4]; 4],
    rhs: [f64; 4],
    counters: &mut Counters,
    w_low: f64,
    w_high: f64,
) -> State {
    let Some(coefficients) = solve4(gram, rhs) else {
        return State::Empty;
    };
    let mut run = Run::new(coefficients);
    for (kind, samples) in frames {
        let scorable = matches!(kind, Kind::Packet);
        score(&mut run, counters, *kind, samples, w_low, w_high, scorable);
    }
    State::Running(run)
}

/// One call's worth of segmental SNR and splice-continuity bookkeeping. Fed
/// one played frame at a time, in playback order, from [`audio::Media::turn`].
pub(crate) struct Gate {
    rate: Option<u32>,
    /// `(w_low, w_high)`, the two frequencies in radians per sample at
    /// `rate` — recomputed only when `rate` changes.
    angular: Option<(f64, f64)>,
    window: usize,
    state: State,
    counters: Counters,
}

impl Gate {
    pub(crate) fn new() -> Self {
        Self {
            rate: None,
            angular: None,
            window: 0,
            state: State::Empty,
            counters: Counters::default(),
        }
    }

    /// Take one played frame: `outcome` is what
    /// [`sipral::MediaSession::playback`] reported for it, `samples` is what
    /// it wrote, and `rate` is the session's current sample rate — read
    /// fresh every call because nothing here assumes it cannot change.
    pub(crate) fn observe(&mut self, outcome: Playback, samples: &[i16], rate: u32) {
        if samples.is_empty() {
            return;
        }
        if self.rate != Some(rate) {
            // a rate this call has not seen before: a fit made under the old
            // one describes nothing under the new one
            self.rate = Some(rate);
            self.angular = Some((angular(FREQ_LOW, rate), angular(FREQ_HIGH, rate)));
            self.window = seed_window(rate);
            self.state = State::Empty;
        }
        let Some((w_low, w_high)) = self.angular else {
            return;
        };
        if matches!(outcome, Playback::Concealed) {
            self.counters.concealed_frames = self.counters.concealed_frames.saturating_add(1);
        }
        match classify(outcome, samples) {
            Classification::Quiet => self.state = State::Empty,
            Classification::Packet => self.take(Kind::Packet, samples, w_low, w_high, true),
            Classification::Concealed => {
                if !matches!(self.state, State::Empty) {
                    self.take(Kind::Concealed, samples, w_low, w_high, false);
                }
                // concealment before any run was even started has nothing to
                // splice-check against and no fit to seed from; it is still
                // counted in `concealed_frames` above
            }
        }
    }

    /// Advance [`State`] by one frame: accumulate it into a fit still being
    /// seeded, complete that fit and score everything collected once it has
    /// enough, or score straight into a fit already running.
    fn take(&mut self, kind: Kind, samples: &[i16], w_low: f64, w_high: f64, scorable: bool) {
        let state = std::mem::replace(&mut self.state, State::Empty);
        self.state = match state {
            State::Empty => {
                if scorable {
                    let mut gram = [[0.0_f64; 4]; 4];
                    let mut rhs = [0.0_f64; 4];
                    accumulate(&mut gram, &mut rhs, 0, samples, w_low, w_high);
                    let collected = samples.len();
                    let frames = vec![(kind, samples.to_vec())];
                    if collected >= self.window {
                        finish_seeding(&frames, gram, rhs, &mut self.counters, w_low, w_high)
                    } else {
                        State::Seeding {
                            frames,
                            gram,
                            rhs,
                            collected,
                        }
                    }
                } else {
                    // only a real, audible frame may start a run — see
                    // `observe`'s own comment on concealment with no run open
                    State::Empty
                }
            }
            State::Seeding {
                mut frames,
                mut gram,
                mut rhs,
                mut collected,
            } => {
                // only a real frame's samples belong in the fit -- a
                // concealed one is the concealer's own guess, and folding it
                // into the Gram matrix and right-hand side would drag the
                // fitted reference toward whatever it guessed rather than
                // the tone actually played, exactly the conflation the
                // module doc says segmental SNR and the splice check both
                // exist to avoid. `collected` still advances either way: it
                // is the elapsed-sample clock `accumulate`'s `base_k` reads,
                // and a concealed frame takes real time same as a real one.
                if scorable {
                    accumulate(&mut gram, &mut rhs, collected, samples, w_low, w_high);
                }
                frames.push((kind, samples.to_vec()));
                collected += samples.len();
                if collected >= self.window {
                    finish_seeding(&frames, gram, rhs, &mut self.counters, w_low, w_high)
                } else {
                    State::Seeding {
                        frames,
                        gram,
                        rhs,
                        collected,
                    }
                }
            }
            State::Running(mut run) => {
                score(
                    &mut run,
                    &mut self.counters,
                    kind,
                    samples,
                    w_low,
                    w_high,
                    scorable,
                );
                State::Running(run)
            }
        };
    }

    /// What this call measured, for the result line and for
    /// [`Report::verdict`].
    pub(crate) fn report(&self) -> Report {
        Report {
            segments: self.counters.segment_count,
            mean_seg_snr_db: if self.counters.segment_count == 0 {
                0.0
            } else {
                self.counters.segment_db_sum / f64::from(self.counters.segment_count)
            },
            concealed_frames: self.counters.concealed_frames,
            edges_checked: self.counters.edges_checked,
            clicks: self.counters.clicks,
        }
    }
}

/// An angular frequency in radians per sample, from a frequency in Hz and a
/// rate in samples per second.
fn angular(freq_hz: f64, rate: u32) -> f64 {
    2.0 * core::f64::consts::PI * freq_hz / f64::from(rate)
}

/// What [`Gate::report`] measured over one call.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(crate) struct Report {
    /// Playback frames scored for segmental SNR: `Playback::Packet`, loud
    /// enough to be the tone.
    pub(crate) segments: u32,
    /// The plain mean of every scored frame's own segmental SNR, in dB.
    pub(crate) mean_seg_snr_db: f64,
    /// Playback frames `Playback::Concealed` reported, whether or not a run
    /// was open to charge them to.
    pub(crate) concealed_frames: u32,
    /// Splices checked for continuity: a run's kind changing between
    /// `Playback::Packet` and `Playback::Concealed`.
    pub(crate) edges_checked: u32,
    /// Of those, the ones whose jump was far enough above the reference's
    /// own to count as a click.
    pub(crate) clicks: u32,
}

impl Report {
    /// Whether this call's audio passes the gate. `Err` names the one thing
    /// that did not hold, the way `Script::verdict` does for the rest of a
    /// flow.
    pub(crate) fn verdict(&self) -> Result<(), String> {
        if self.segments == 0 {
            return Err("the audio quality gate scored no arriving frames".to_owned());
        }
        if self.clicks > 0 {
            return Err(format!(
                "{} of {} concealment splice(s) clicked",
                self.clicks, self.edges_checked
            ));
        }
        if self.mean_seg_snr_db < MIN_SEGMENTAL_SNR_DB {
            return Err(format!(
                "segmental SNR {:.1} dB over {} frames is under the {:.1} dB floor",
                self.mean_seg_snr_db, self.segments, MIN_SEGMENTAL_SNR_DB
            ));
        }
        Ok(())
    }

    /// The measured numbers, for the result line — printed whether or not
    /// the gate passed, so a profile's own line always says what it found.
    pub(crate) fn summary(&self) -> String {
        format!(
            "segSNR {:.1}dB over {} frames, concealed {}, clicks {}/{}",
            self.mean_seg_snr_db,
            self.segments,
            self.concealed_frames,
            self.clicks,
            self.edges_checked
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{FREQ_HIGH, FREQ_LOW, Gate, MIN_SEGMENTAL_SNR_DB, angular};
    use sipral::Playback;

    const RATE: u32 = 8_000;
    const FRAME: usize = 160;

    /// The lab's own tone, exactly as `interop/asterisk/extensions.conf` and
    /// `interop/freeswitch/lab.xml` describe it, at whatever amplitude and
    /// starting phase a test wants — the far end's own generator promises
    /// neither, which is the whole reason a fit is taken at all.
    // amplitudes chosen by every caller below stay well inside i16 range, so
    // the truncation this cast could otherwise do never happens
    #[allow(clippy::cast_possible_truncation)]
    fn lab_tone(
        n: u64,
        amplitude_low: f64,
        amplitude_high: f64,
        phase_low: f64,
        phase_high: f64,
    ) -> i16 {
        let w_low = angular(FREQ_LOW, RATE);
        let w_high = angular(FREQ_HIGH, RATE);
        #[allow(clippy::cast_precision_loss)]
        let n = n as f64;
        let value = amplitude_low * (w_low * n + phase_low).sin()
            + amplitude_high * (w_high * n + phase_high).sin();
        value.round() as i16
    }

    fn frame(
        start: u64,
        amplitude_low: f64,
        amplitude_high: f64,
        phase_low: f64,
        phase_high: f64,
    ) -> Vec<i16> {
        (0..FRAME as u64)
            .map(|k| {
                lab_tone(
                    start + k,
                    amplitude_low,
                    amplitude_high,
                    phase_low,
                    phase_high,
                )
            })
            .collect()
    }

    /// A run of clean frames at an amplitude and phase the gate was never
    /// told in advance passes with a high segmental SNR and no clicks — the
    /// gate's own idea of a good call, and the proof that the fit actually
    /// recovers an unannounced signal rather than assuming one.
    #[test]
    fn a_clean_run_passes_with_a_high_segmental_snr() {
        let mut gate = Gate::new();
        for i in 0..20_u64 {
            let f = frame(i * FRAME as u64, 6_500.0, 4_200.0, 0.7, 2.1);
            gate.observe(Playback::Packet, &f, RATE);
        }
        let report = gate.report();
        assert!(report.segments > 0, "no frame was scored: {report:?}");
        assert_eq!(report.clicks, 0, "a clean run clicked: {report:?}");
        assert!(
            report.mean_seg_snr_db > MIN_SEGMENTAL_SNR_DB + 20.0,
            "a clean, unannounced tone scored only {:.1} dB",
            report.mean_seg_snr_db
        );
        assert!(report.verdict().is_ok(), "{:?}", report.verdict());
    }

    /// A run shorter than one seed window never gets a fit, and none of its
    /// frames are scored — a spurt this short simply has nothing measured
    /// about it, rather than a fit taken on too little to trust.
    #[test]
    fn a_run_shorter_than_the_seed_window_is_never_scored() {
        let mut gate = Gate::new();
        for i in 0..3_u64 {
            let f = frame(i * FRAME as u64, 6_500.0, 4_200.0, 0.0, 0.0);
            gate.observe(Playback::Packet, &f, RATE);
        }
        gate.observe(Playback::Silence, &vec![0_i16; FRAME], RATE);
        let report = gate.report();
        assert_eq!(report.segments, 0, "{report:?}");
    }

    /// A concealed gap in the middle of a run, spliced back onto the exact
    /// same continuing tone on both edges, does not click and does not
    /// depress the segmental SNR of the real frames either side of it —
    /// concealment is not itself a defect. The gap sits after the seed
    /// window, so both splices are checked against an established fit.
    #[test]
    fn a_cleanly_spliced_concealment_gap_does_not_click() {
        let mut gate = Gate::new();
        let mut n = 0_u64;
        for _ in 0..8 {
            gate.observe(
                Playback::Packet,
                &frame(n, 6_500.0, 4_200.0, 0.0, 0.0),
                RATE,
            );
            n += FRAME as u64;
        }
        for _ in 0..3 {
            gate.observe(
                Playback::Concealed,
                &frame(n, 6_500.0, 4_200.0, 0.0, 0.0),
                RATE,
            );
            n += FRAME as u64;
        }
        for _ in 0..8 {
            gate.observe(
                Playback::Packet,
                &frame(n, 6_500.0, 4_200.0, 0.0, 0.0),
                RATE,
            );
            n += FRAME as u64;
        }
        let report = gate.report();
        assert_eq!(
            report.edges_checked, 2,
            "both splices should be checked: {report:?}"
        );
        assert_eq!(
            report.clicks, 0,
            "a perfectly continued tone clicked: {report:?}"
        );
        assert_eq!(report.concealed_frames, 3);
    }

    /// The shape the first lab runs flagged, four calls in ten on `mobile`:
    /// a concealment whose phase drifts off the tone's, and a resume that
    /// cross-fades out of it, so the audio at the splice is a quarter of a
    /// cycle from the reference, steep where the reference sits at a peak.
    /// Every step across the splice is one the tone itself takes; judged
    /// against the reference's own step there, the resume was a click.
    #[test]
    fn a_smooth_resume_away_from_the_tones_phase_does_not_click() {
        let amplitude = 6_500.0;
        // a cosine: every frame boundary, a multiple of 160 samples, is
        // exactly one of its peaks, where its own step is at its smallest
        let peak = core::f64::consts::FRAC_PI_2;
        let w_low = angular(FREQ_LOW, RATE);
        // a quarter of a cycle at 350 Hz, in samples
        let drift = 6.0;
        #[allow(clippy::cast_possible_truncation, clippy::cast_precision_loss)]
        let at = |n: f64| (amplitude * (w_low * n + peak).sin()).round() as i16;

        let mut gate = Gate::new();
        let mut n = 0_u64;
        for _ in 0..8 {
            gate.observe(Playback::Packet, &frame(n, amplitude, 0.0, peak, 0.0), RATE);
            n += FRAME as u64;
        }
        // the extension starts on the tone and drifts a quarter cycle off it
        #[allow(clippy::cast_precision_loss)]
        let concealed: Vec<i16> = (0..FRAME)
            .map(|k| at(n as f64 + k as f64 + drift * k as f64 / FRAME as f64))
            .collect();
        gate.observe(Playback::Concealed, &concealed, RATE);
        n += FRAME as u64;
        // and the stream resumes from where the extension had got to
        #[allow(clippy::cast_precision_loss)]
        let resumed: Vec<i16> = (0..FRAME)
            .map(|k| at((n + k as u64) as f64 + drift))
            .collect();
        gate.observe(Playback::Packet, &resumed, RATE);

        let report = gate.report();
        assert_eq!(report.edges_checked, 2, "both splices checked: {report:?}");
        assert_eq!(
            report.clicks, 0,
            "a resume as smooth as the tone itself clicked: {report:?}"
        );
    }

    /// A splice onto a signal with a jump in it — a sample yanked to the
    /// opposite extreme, the shape a jitter buffer that lost its place or a
    /// concealer with the wrong estimate would produce — is exactly the
    /// discontinuity the gate exists to catch.
    #[test]
    fn a_splice_with_a_jump_clicks() {
        let mut gate = Gate::new();
        let mut n = 0_u64;
        for _ in 0..8 {
            gate.observe(
                Playback::Packet,
                &frame(n, 6_500.0, 4_200.0, 0.0, 0.0),
                RATE,
            );
            n += FRAME as u64;
        }
        let mut jumped = frame(n, 6_500.0, 4_200.0, 0.0, 0.0);
        jumped[0] = jumped[0].saturating_add(9_000);
        gate.observe(Playback::Concealed, &jumped, RATE);
        let report = gate.report();
        assert!(
            report.clicks >= 1,
            "a jump onto the splice never clicked: {report:?}"
        );
        assert!(report.verdict().is_err());
    }

    /// A concealed frame landing inside the seed window -- before the run
    /// has a fit yet -- must not be folded into that fit: the far end's own
    /// tone continued underneath the gap even though nothing arrived to say
    /// so, and the fit has to describe that tone, not whatever the concealer
    /// guessed. A silent concealed frame here is a genuine discontinuity
    /// against the tone either side of it -- both splices correctly click,
    /// same as `a_splice_with_a_jump_clicks` -- but the eight clean, fully
    /// unimpaired `Packet` frames that follow must still score close to the
    /// ceiling: a fit that let the concealed silence into the Gram matrix
    /// and right-hand side would instead chase a signal that never played,
    /// depressing every frame scored against it for the rest of the run,
    /// which is what this run measured before the fit excluded
    /// `Kind::Concealed` samples from accumulation.
    #[test]
    fn a_concealed_frame_inside_the_seed_window_is_not_fitted() {
        let mut gate = Gate::new();
        gate.observe(
            Playback::Packet,
            &frame(0, 6_500.0, 4_200.0, 0.0, 0.0),
            RATE,
        );
        gate.observe(Playback::Concealed, &vec![0_i16; FRAME], RATE);
        let mut n = 2 * FRAME as u64;
        for _ in 0..8 {
            gate.observe(
                Playback::Packet,
                &frame(n, 6_500.0, 4_200.0, 0.0, 0.0),
                RATE,
            );
            n += FRAME as u64;
        }
        let report = gate.report();
        assert!(
            report.mean_seg_snr_db > MIN_SEGMENTAL_SNR_DB + 15.0,
            "a concealed frame inside the seed window pulled the fit toward \
             it instead of the tone: {report:?}"
        );
    }

    /// Frames the far end never sent loudly enough to be the tone — the
    /// pauses between spurts — neither seed a run nor get scored: the gate
    /// reports nothing to say about them, rather than treating silence
    /// itself as noise against a tone that was never due.
    #[test]
    fn quiet_frames_are_not_scored() {
        let mut gate = Gate::new();
        let quiet = vec![0_i16; FRAME];
        for _ in 0..10 {
            gate.observe(Playback::Silence, &quiet, RATE);
        }
        let report = gate.report();
        assert_eq!(report.segments, 0);
        assert_eq!(report.edges_checked, 0);
        assert!(report.verdict().is_err());
    }
}
