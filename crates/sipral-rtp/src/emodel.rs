// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A simplified ITU-T G.107 E-model: the transmission rating factor R and
//! the mean opinion scores RFC 3611 §4.7.5 asks a VoIP Metrics block to
//! carry, computed from what a two-party RTP endpoint can actually measure.
//!
//! The full E-model (G.107 §7) takes some twenty transmission parameters that an RTP endpoint
//! with no analogue tail cannot observe. G.107 §7.7 recommends the defaults for those, which give
//! `R = 93.2` (`Ro - Is` in equation 7-1, with `Id`, `Ie,eff` and `A` at zero). That figure is the
//! baseline here; every input to `Ro` and `Is` stays at its Table 3 default, so recomputing them
//! would only reproduce the same constant.
//!
//! What this module does compute, from what a call actually observes:
//!
//! - `Id`, the delay impairment (§7.4), from the one-way delay a call can
//!   estimate — but only its `Idd` (equation 7-27/7-28) term. `Idte`
//!   (talker echo) and `Idle` (listener echo) are left at zero: they are
//!   driven by the mean one-way echo-path delay `T`, the round-trip delay
//!   `Tr` and the weighted echo path loss `WEPL`, and this stack's default
//!   assumption is a digital connection with no analogue echo path, i.e.
//!   `T = Tr = 0` and `WEPL` at its default of 110 dB — which is exactly
//!   the G.107 Table 3 default, and at that default both terms round to
//!   zero (§7.4: "For values of `T < 1 ms`, the talker echo should be
//!   considered as sidetone, i.e. `Idte = 0`").
//! - `Ie,eff`, the codec and packet-loss impairment (§7.5, equation 7-29),
//!   from the codec-specific `Ie`/`Bpl` pair ITU-T G.113 Appendix I
//!   tabulates and the packet loss a call measures.
//!
//! `A`, the advantage factor (§7.6), stays at its default of zero: none of
//! this stack's provisional examples (cellular mobility, satellite) apply
//! to a wired or Wi-Fi softphone call, and inventing a value here would be
//! exactly the guess G.107 warns against.

use crate::rtcp_xr::UNAVAILABLE;

/// `Ro - Is` at every G.107 Table 3 default value (§7.7), cited rather than computed from
/// equations 7-2 to 7-17 (see the module docs).
const R_BASELINE: f64 = 93.2;

/// Delay-sensitivity class `sT` (Table 1, "Default": "Must be used for
/// ... [when the] targeted user group and delay requirements are
/// unknown", which is every call this stack places).
const DELAY_SENSITIVITY: f64 = 1.0;

/// Minimum perceivable delay `mT`, in milliseconds, for the same "Default"
/// class (Table 1).
const MIN_PERCEIVABLE_DELAY_MS: f64 = 100.0;

/// Advantage factor `A` (§7.6): zero, "conventional (wirebound)" in
/// Table 2's terms, and the only entry in that table with no upper bound
/// that this stack could claim without inventing one.
const ADVANTAGE_FACTOR: f64 = 0.0;

/// The two codec-specific numbers G.113 Appendix I tabulates: the
/// equipment impairment factor at zero packet loss, and the packet-loss
/// robustness factor equation 7-29 uses to turn a loss rate into
/// `Ie,eff`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CodecQualityModel {
    /// `Ie`: the codec's own impairment at zero packet loss.
    pub ie: f64,
    /// `Bpl`: robustness to packet loss; larger is more robust.
    pub bpl: f64,
}

/// A codec family with a G.113 Appendix I (Table I.4) `Ie`/`Bpl` entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecFamily {
    /// G.711, mu-law or A-law: one quantiser design, and G.113 Table I.4
    /// tabulates both under the one entry "G.711".
    G711,
    /// G.711 whose lost frames are concealed by waveform extension, the
    /// receiver repeating the last pitch period: G.107 Table 3, Note 5, "the
    /// Bpl must match the codec, packet size and packet loss concealment
    /// (PLC) assumed".
    G711Concealed,
}

/// G.113 Table I.4's entry for one codec family, without packet loss: `Ie`
/// and `Bpl` at `Ppl = 0`. Not every codec this stack can carry has one:
/// see [`codec_quality_model`].
#[must_use]
pub const fn codec_quality_model(family: CodecFamily) -> CodecQualityModel {
    match family {
        // ITU-T G.113 (09/2024) Table I.4, "G.711, 10 ms, PLC: None":
        // Ie = 0, Bpl = 4.3 -- the same Bpl G.107 Table 3 lists as its own
        // default, since an unconcealed G.711 stream is the model's own
        // reference case.
        CodecFamily::G711 => CodecQualityModel { ie: 0.0, bpl: 4.3 },
        // G.113 Appendix I, G.711 with the packet loss concealment of G.711
        // Appendix I: no impairment of its own, and Bpl = 25.1 under random
        // loss
        CodecFamily::G711Concealed => CodecQualityModel { ie: 0.0, bpl: 25.1 },
    }
}

/// How bursty measured packet loss is, relative to independent loss at the
/// same rate (G.107 equation 7-29's `BurstR`, §7.5).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BurstRatio(f64);

impl BurstRatio {
    /// `BurstR = 1`: "when packet loss is random (i.e., independent)"
    /// (§7.5). The default this module uses when a call has not measured
    /// its own burst/gap statistics (RFC 3611 §4.7.2) yet, and the only
    /// value G.113 recommends using at all outside codecs with an
    /// efficient codec-state-based PLC (Bpl >= 16).
    pub const RANDOM: Self = Self(1.0);

    /// A burst ratio measured some other way. `ratio` is clamped to `1.0`
    /// or above: `BurstR < 1` has no meaning in equation 7-29 ("when
    /// packet loss is bursty (i.e., dependent) BurstR > 1").
    #[must_use]
    pub fn new(ratio: f64) -> Self {
        Self(if ratio.is_finite() {
            ratio.max(1.0)
        } else {
            1.0
        })
    }
}

/// What this module was asked to rate: the one-way delay and packet loss a
/// call measured, and the codec it measured them for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct EModelInputs {
    /// The estimated one-way delay end to end, in milliseconds (G.107's
    /// `Ta`, §7.4). RFC 3611 §4.7.3's "one way symmetric voice path delay"
    /// worked example is one way to arrive at it from a round-trip and two
    /// end-system delays.
    pub one_way_delay_ms: u32,
    /// The percentage of packets that never reached the decoder, `Ppl` in
    /// equation 7-29, `0.0..=100.0`: those the network lost and those the
    /// jitter buffer discarded, which RFC 3611 §4.7.1 says "have equal
    /// effect on the quality of the voice stream".
    pub packet_loss_percent: f64,
    /// `BurstR`, how bursty that loss was.
    pub burst_ratio: BurstRatio,
    /// The codec in use, if G.113 tabulates `Ie`/`Bpl` for it. `None`
    /// reports every field in [`EModelReport`] as unavailable, per RFC
    /// 3611 §4.7.5's instruction to send the sentinel rather than a guess.
    pub codec: Option<CodecQualityModel>,
}

/// The four RTCP-XR VoIP Metrics quality fields (§4.7.5), computed by this
/// module or reported as unavailable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EModelReport {
    /// The RTP-segment R factor, `0..=100`, or [`UNAVAILABLE`].
    pub r_factor: u8,
    /// The R factor of a network segment external to this RTP session.
    /// This module never has one to report and always returns
    /// [`UNAVAILABLE`] here.
    pub ext_r_factor: u8,
    /// Estimated listening-quality MOS x 10, `10..=50`, or
    /// [`UNAVAILABLE`]. Excludes the effect of delay (§4.7.5).
    pub mos_lq: u8,
    /// Estimated conversational-quality MOS x 10, `10..=50`, or
    /// [`UNAVAILABLE`]. Includes the effect of delay (§4.7.5).
    pub mos_cq: u8,
}

impl EModelReport {
    /// The all-127 report §4.7.5 asks for when a metric "is unavailable".
    const fn unavailable() -> Self {
        Self {
            r_factor: UNAVAILABLE,
            ext_r_factor: UNAVAILABLE,
            mos_lq: UNAVAILABLE,
            mos_cq: UNAVAILABLE,
        }
    }
}

/// `Idd`, equations 7-27 and 7-28: the impairment from absolute delay
/// alone, at the "Default" delay-sensitivity class (Table 1).
fn delay_impairment(one_way_delay_ms: f64) -> f64 {
    if one_way_delay_ms <= MIN_PERCEIVABLE_DELAY_MS {
        return 0.0;
    }
    let x = (one_way_delay_ms / MIN_PERCEIVABLE_DELAY_MS).log2();
    let exponent = 6.0 * DELAY_SENSITIVITY;
    let inverse_exponent = exponent.recip();
    25.0 * ((1.0 + x.powf(exponent)).powf(inverse_exponent)
        - 3.0 * (1.0 + (x / 3.0).powf(exponent)).powf(inverse_exponent)
        + 2.0)
}

/// `Ie,eff`, equation 7-29: the codec's own impairment folded together
/// with what packet loss does to it,
/// `Ie + (95 - Ie) * Ppl / (Ppl / BurstR + Bpl)`. Only the `Ppl` in the
/// denominator is divided by `BurstR`, so loss in bursts weighs more than
/// the same loss at random (`BurstR > 1`).
fn effective_equipment_impairment(
    codec: CodecQualityModel,
    ppl_percent: f64,
    burst_ratio: f64,
) -> f64 {
    if ppl_percent <= 0.0 {
        return codec.ie;
    }
    codec.ie + (95.0 - codec.ie) * (ppl_percent / (ppl_percent / burst_ratio + codec.bpl))
}

/// Equation B-4: mean opinion score from a transmission rating factor.
fn mos_from_r(r: f64) -> f64 {
    if r <= 0.0 {
        1.0
    } else if r >= 100.0 {
        4.5
    } else {
        1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7.0e-6
    }
}

/// `R` field a value in `0..=100` can hold, rounded to the nearest integer
/// (§4.7.5: "expressed as an integer in the range 0 to 100").
fn quantize_r(r: f64) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped into 0.0..=100.0 immediately above"
    )]
    let clamped = r.clamp(0.0, 100.0).round() as u8;
    clamped
}

/// A MOS field's value: "expressed as an integer in the range 10 to 50,
/// corresponding to MOS x 10" (§4.7.5), rounded to the nearest integer.
fn quantize_mos(mos: f64) -> u8 {
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "clamped into 10.0..=50.0 immediately above"
    )]
    let clamped = (mos * 10.0).clamp(10.0, 50.0).round() as u8;
    clamped
}

/// Rate one segment of a call: the R factor and the two mean opinion
/// scores RFC 3611 §4.7.5 asks a VoIP Metrics block to carry.
#[must_use]
pub fn evaluate(inputs: EModelInputs) -> EModelReport {
    let Some(codec) = inputs.codec else {
        return EModelReport::unavailable();
    };
    let id = delay_impairment(f64::from(inputs.one_way_delay_ms));
    let ppl = inputs.packet_loss_percent.clamp(0.0, 100.0);
    let ie_eff = effective_equipment_impairment(codec, ppl, inputs.burst_ratio.0);

    let r_conversational = (R_BASELINE - id - ie_eff + ADVANTAGE_FACTOR).clamp(0.0, 100.0);
    // MOS-LQ "is defined as not including the effects of delay" (§4.7.5),
    // so it is rated from the same connection with `Id` left out.
    let r_listening = (R_BASELINE - ie_eff + ADVANTAGE_FACTOR).clamp(0.0, 100.0);

    EModelReport {
        r_factor: quantize_r(r_conversational),
        ext_r_factor: UNAVAILABLE,
        mos_lq: quantize_mos(mos_from_r(r_listening)),
        mos_cq: quantize_mos(mos_from_r(r_conversational)),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BurstRatio, CodecFamily, EModelInputs, R_BASELINE, codec_quality_model, delay_impairment,
        effective_equipment_impairment, evaluate, mos_from_r,
    };
    use crate::rtcp_xr::UNAVAILABLE;

    #[test]
    fn the_g107_default_baseline_is_the_figure_the_recommendation_itself_states() {
        // G.107 §7.7: "If all parameters are set to the default values,
        // the calculation results in ... a rating factor of R = 93.2."
        assert!((R_BASELINE - 93.2).abs() < f64::EPSILON);
    }

    #[test]
    fn zero_delay_and_zero_loss_reproduces_the_g107_default_r_of_93_2() {
        let report = evaluate(EModelInputs {
            one_way_delay_ms: 0,
            packet_loss_percent: 0.0,
            burst_ratio: BurstRatio::RANDOM,
            codec: Some(codec_quality_model(CodecFamily::G711)),
        });
        // R=93.2 rounds to 93; MOS from equation B-4 at R=93.2 is computed
        // by hand below and rounds to 4.4 (44 in the field's x10 units).
        assert_eq!(report.r_factor, 93);
        assert_eq!(report.mos_cq, 44);
        assert_eq!(report.mos_lq, 44, "no delay was fed in, so LQ == CQ here");
        assert_eq!(report.ext_r_factor, UNAVAILABLE);
    }

    #[test]
    fn mos_from_r_matches_the_g107_table_b_1_lower_limit_at_r_90() {
        // Annex B, Table B.1: "R-value (lower limit) 90 -> MOSCQE
        // (lower limit) 4.34".
        let mos = mos_from_r(90.0);
        assert!(
            (mos - 4.34).abs() < 0.01,
            "MOS(90) = {mos}, table B.1 says 4.34"
        );
    }

    #[test]
    fn mos_from_r_matches_the_g107_table_b_1_lower_limit_at_r_70() {
        // Table B.1: "70 -> 3.60".
        let mos = mos_from_r(70.0);
        assert!(
            (mos - 3.60).abs() < 0.01,
            "MOS(70) = {mos}, table B.1 says 3.60"
        );
    }

    #[test]
    fn delay_at_or_under_the_minimum_perceivable_delay_has_no_impairment() {
        // Equation 7-27: "For Ta <= mT: Idd = 0", mT = 100 ms at the
        // Default class (Table 1).
        assert!((delay_impairment(0.0)).abs() < f64::EPSILON);
        assert!((delay_impairment(100.0)).abs() < f64::EPSILON);
    }

    #[test]
    fn a_long_one_way_delay_measurably_degrades_r() {
        let short = evaluate(EModelInputs {
            one_way_delay_ms: 100,
            packet_loss_percent: 0.0,
            burst_ratio: BurstRatio::RANDOM,
            codec: Some(codec_quality_model(CodecFamily::G711)),
        });
        let long = evaluate(EModelInputs {
            one_way_delay_ms: 400,
            packet_loss_percent: 0.0,
            burst_ratio: BurstRatio::RANDOM,
            codec: Some(codec_quality_model(CodecFamily::G711)),
        });
        assert!(long.r_factor < short.r_factor);
        assert!(
            long.mos_cq < short.mos_cq,
            "conversational MOS falls with delay"
        );
        assert_eq!(
            long.mos_lq, short.mos_lq,
            "listening MOS excludes delay (§4.7.5), so it should not move"
        );
    }

    #[test]
    fn packet_loss_at_zero_percent_leaves_ie_eff_at_the_codecs_own_ie() {
        // Equation 7-29's own note: "the effective equipment impairment
        // factor in the case of Ppl = 0 (no packet-loss) is equal to the
        // Ie value defined in Appendix I of [ITU-T G.113]".
        let model = codec_quality_model(CodecFamily::G711);
        let ie_eff = effective_equipment_impairment(model, 0.0, 1.0);
        assert!((ie_eff - model.ie).abs() < f64::EPSILON);
    }

    #[test]
    fn heavier_packet_loss_measurably_degrades_r() {
        let clean = evaluate(EModelInputs {
            one_way_delay_ms: 0,
            packet_loss_percent: 0.0,
            burst_ratio: BurstRatio::RANDOM,
            codec: Some(codec_quality_model(CodecFamily::G711)),
        });
        let lossy = evaluate(EModelInputs {
            one_way_delay_ms: 0,
            packet_loss_percent: 5.0,
            burst_ratio: BurstRatio::RANDOM,
            codec: Some(codec_quality_model(CodecFamily::G711)),
        });
        assert!(lossy.r_factor < clean.r_factor);
        assert!(lossy.mos_cq < clean.mos_cq);
    }

    #[test]
    fn a_codec_g113_does_not_tabulate_is_reported_unavailable_not_guessed() {
        let report = evaluate(EModelInputs {
            one_way_delay_ms: 40,
            packet_loss_percent: 1.0,
            burst_ratio: BurstRatio::RANDOM,
            codec: None,
        });
        assert_eq!(report.r_factor, UNAVAILABLE);
        assert_eq!(report.mos_lq, UNAVAILABLE);
        assert_eq!(report.mos_cq, UNAVAILABLE);
    }

    #[test]
    fn a_burst_ratio_below_one_is_clamped_to_one() {
        // §7.5: "when packet loss is random (i.e., independent) BurstR =
        // 1", and the formula has no meaning below that.
        assert!((BurstRatio::new(0.2).0 - 1.0).abs() < f64::EPSILON);
        assert!((BurstRatio::new(f64::NAN).0 - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn burstier_loss_at_the_same_rate_is_rated_worse_than_random_loss() {
        // §7.5: BurstR > 1 is loss in bursts, and equation 7-29 divides only
        // the denominator's Ppl by it, so the same rate in bursts costs more.
        // 5 % at BurstR 2 on Bpl 4.3: Ie,eff = 95 * 5 / (2.5 + 4.3) = 69.85,
        // R = 93.2 - 69.85 = 23.35
        let model = codec_quality_model(CodecFamily::G711);
        let ie_eff = effective_equipment_impairment(model, 5.0, 2.0);
        assert!((ie_eff - 95.0 * 5.0 / 6.8).abs() < 1e-9, "{ie_eff}");
        let random = evaluate(EModelInputs {
            one_way_delay_ms: 0,
            packet_loss_percent: 5.0,
            burst_ratio: BurstRatio::RANDOM,
            codec: Some(codec_quality_model(CodecFamily::G711)),
        });
        let bursty = evaluate(EModelInputs {
            one_way_delay_ms: 0,
            packet_loss_percent: 5.0,
            burst_ratio: BurstRatio::new(4.0),
            codec: Some(codec_quality_model(CodecFamily::G711)),
        });
        assert!(bursty.r_factor < random.r_factor);
        let two = evaluate(EModelInputs {
            one_way_delay_ms: 0,
            packet_loss_percent: 5.0,
            burst_ratio: BurstRatio::new(2.0),
            codec: Some(model),
        });
        assert_eq!(two.r_factor, 23);
    }

    #[test]
    fn codec_quality_model_matches_g113_table_i_4_for_g711() {
        let model = codec_quality_model(CodecFamily::G711);
        assert!((model.ie - 0.0).abs() < f64::EPSILON);
        assert!((model.bpl - 4.3).abs() < f64::EPSILON);
        let concealed = codec_quality_model(CodecFamily::G711Concealed);
        assert!((concealed.ie - 0.0).abs() < f64::EPSILON);
        assert!((concealed.bpl - 25.1).abs() < f64::EPSILON);
    }
}
