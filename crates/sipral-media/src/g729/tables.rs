// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The constants of ITU-T G.729 Annex A, and of Annex B's silence
//! compression over it.
//!
//! # Where each table came from
//!
//! Three kinds of constant live here, and they came from three places.
//!
//! **Constants the text prints or defines by a formula** were written from
//! the Recommendation and are checked against it by the tests at the end:
//! the gain predictor's four coefficients (§3.9.1, equation 69), the output
//! high-pass filter (§4.2.5, equation 91), the starting point of the LSF
//! predictor's memory (§4.3, Table 9: `iπ/11`), and the lookup tables behind
//! the arithmetic that Table 12 names without printing — the cosine and its
//! slope, `2^x` and the inverse square root are their closed forms entry for
//! entry, and `log2` is its closed form to within one unit, the test saying
//! which way each entry was rounded.
//!
//! **Tables the text neither prints nor defines** are the ones a training
//! procedure produced: the two stages of the LSP quantizer, the MA
//! predictor, the two gain codebooks and the maps between their rows and
//! the codewords on the wire, and the interpolation filter `b30`. §2.4 makes
//! the software annex normative for these, and they exist nowhere else. Their
//! numbers were copied mechanically, by a script that read nothing but the
//! initialised numeric arrays of the Annex A table file, into a list of
//! values and dimensions; the arrays below were written from that list and
//! named here from what the Recommendation calls each table. No other part of
//! the software annex was read. The mapping, ours on the left, and for the
//! tables with a closed form, which of the two the values here were taken
//! from:
//!
//! | Here | The Recommendation's name | Key in the extracted list |
//! |---|---|---|
//! | [`FIRST_STAGE`] | `L1`, §3.2.4 | `annex_a.lspcb1` |
//! | [`SECOND_STAGE_LOW`] | `L2`, §3.2.4 | `annex_a.lspcb2`, columns 0–4 |
//! | [`SECOND_STAGE_HIGH`] | `L3`, §3.2.4 | `annex_a.lspcb2`, columns 5–9 |
//! | [`MA_PREDICTOR`] | `p̂(i,k)`, equation 20 | `annex_a.fg` |
//! | [`MA_CURRENT_WEIGHT`] | `1 − Σ p̂(i,k)`, equation 20 | `annex_a.fg_sum` |
//! | [`MA_CURRENT_WEIGHT_INVERSE`] | its reciprocal, equation 92 | `annex_a.fg_sum_inv` |
//! | [`INTERPOLATION_B30`] | `b30`, §3.7.1 | `annex_a.inter_3l` |
//! | [`GA`] | `GA`, §3.9.2 | `annex_a.gbk1` |
//! | [`GB`] | `GB`, §3.9.2 | `annex_a.gbk2` |
//! | [`GA_ROW`] | the index mapping of §3.9.3, decoding side | `annex_a.imap1` |
//! | [`GB_ROW`] | the same for `GB` | `annex_a.imap2` |
//! | [`GA_CODEWORD`] | the index mapping of §3.9.3, encoding side | `annex_a.map1`; equals the inverse of [`GA_ROW`] |
//! | [`GB_CODEWORD`] | the same for `GB` | `annex_a.map2`; equals the inverse of [`GB_ROW`] |
//! | [`PRESELECTION_SLOPES`] | the preselection of §3.9.2 | `annex_a.coef`, column 0 |
//! | [`PRESELECTION_OFFSETS`] | the same | `annex_a.L_coef`, column 1 |
//! | [`GA_THRESHOLDS`] | the same, for `GA` | `annex_a.thr1` |
//! | [`GB_THRESHOLDS`] | the same, for `GB` | `annex_a.thr2` |
//! | [`LP_WINDOW`] | `wlp(n)`, equation 3 | `annex_a.hamwindow`; equals the formula times 32767, rounded |
//! | [`LAG_WINDOW`] | `wlag(k)`, equation 6, over 1.0001 | `annex_ba_ld8a.lag_h` and `annex_ba_ld8a.lag_l`, twelve lags, whose first ten equal `annex_a.lag_h` and `annex_a.lag_l`; the formula to within 60 units in 2^31 |
//! | [`GRID`] | the grid of A.3.2.3 | `annex_a.grid`; equals `cos(jπ/50)` truncated, but for its two ends |
//! | [`ARCCOS_SLOPE`] | the inverse slopes of Table 12's cosine | `annex_a.slope_acos`; equals `2^20` over each segment's fall in [`COSINE`], its ends taken as ±32768, rounded |
//! | [`INPUT_HIGH_PASS_ZEROS`] | equation 1, numerator | computed; equals `annex_a.b140` |
//! | [`INPUT_HIGH_PASS_POLES`] | equation 1, denominator | computed; equals `annex_a.a140` |
//! | [`COSINE`] | Table 12, "LSF to LSP conversion" | `annex_a.table2`; equals `cos(iπ/64)` rounded |
//! | [`COSINE_SLOPE`] | its slopes | `annex_a.slope_cos`; equals the rounded difference of cosines |
//! | [`POWER_OF_TWO`] | Table 12, "2^x computation" | `annex_a.tabpow`; equals `2^(i/32)` rounded |
//! | [`LOG2`] | Table 12, "base 2 logarithm" | `annex_a.tablog`; `log2(1 + i/32)` to within one |
//! | [`INVERSE_SQRT`] | Table 12, "inverse square root" | `annex_a.tabsqr`; equals `1/√(1 + i/16)` rounded |
//! | [`INITIAL_LSF`] | `l̂ = iπ/11`, Table 9 | computed, truncated; equals `annex_ba_ld8a.freq_prev_reset` |
//! | [`GAIN_PREDICTOR`] | `b1..b4`, equation 69 | computed; equals `annex_a.pred` |
//! | [`OUTPUT_HIGH_PASS_ZEROS`] | equation 91, numerator | computed; equals `annex_a.b100` |
//! | [`OUTPUT_HIGH_PASS_POLES`] | equation 91, denominator | computed; equals `annex_a.a100` |
//!
//! Annex B's own tables came the same way, from its table file for the
//! silence compression (and, for the twelve-lag window above, its version
//! of the Annex A table file), with the same script and nothing else of
//! that software read:
//!
//! | Here | The Recommendation's name | Key in the extracted list |
//! |---|---|---|
//! | [`NOISE_MA_PREDICTOR`] | B.18's two predictors | computed from [`MA_PREDICTOR`] by equation B.18 |
//! | [`NOISE_MA_CURRENT_WEIGHT`] | their `1 − Σ p̂` | `annex_ba_dtx.noise_fg_sum` |
//! | [`NOISE_MA_CURRENT_WEIGHT_INVERSE`] | its reciprocal | `annex_ba_dtx.noise_fg_sum_inv` |
//! | [`SID_FIRST_STAGE_ROWS`] | the subset of `L1`, B.4.2.2 item 2 | `annex_ba_dtx.PtrTab_1` |
//! | [`SID_FIRST_STAGE_SCALE`] | not named; it scales the first stage's error per predictor | `annex_ba_dtx.Mp` |
//! | [`SID_SECOND_STAGE_ROWS`] | the subsets of `L2` and `L3`, item 3 | `annex_ba_dtx.PtrTab_2` |
//! | [`SID_GAINS`] | B.4.2.1's levels as gains | `annex_ba_dtx.tab_Sidgain`; the levels' square roots, Q3, to within 1% and a unit |
//! | [`SID_ENERGY_FACTOR`] | equation B.15's factor | `annex_ba_dtx.fact`; equals the formula, rounded |
//! | [`SID_ENERGY_HEADROOM`] | not named | `annex_ba_dtx.marg` |
//! | [`LOW_BAND_CORRELATION`] | B.3.1.3's low-band filter `h`, as `hᵀRh` reads it | `annex_ba_dtx.lbf_corr` |
//! | [`LOUD_FRAMES_MANTISSA`] | B.3.2's average over the loud frames | `annex_ba_dtx.factor_fx`; `32/(32 − n)` as a mantissa |
//! | [`LOUD_FRAMES_SHIFT`] | the same | `annex_ba_dtx.shift_fx`; its shift |
//!
//! Where a name above says "not named", the text does not mention the
//! table: which values the conformance streams need is what placed it,
//! and the code that uses it says how.
//!
//! `b30` is described in the text — a Hamming-windowed sinc truncated at ±29,
//! cut off at 3600 Hz in the three-times oversampled domain — but not closely
//! enough to reproduce: the window's exact length and the normalisation are
//! not stated. The test at the end checks that the table is that filter to
//! within a few units in the last place and has its zeros where the sinc
//! does, which is the most the description supports, and the table's own
//! values are the ones used.
//!
//! **One constant is neither**: [`INITIAL_LSP`], the cosines the decoder
//! interpolates its first subframe from. Table 9 gives them as the cosines of
//! `iπ/11`, and the conformance streams do not decode from that state — the
//! first subframe of eight of the ten Annex A streams comes out different.
//! The values here are the state the streams do decode from, confirmed on
//! the first subframe of all ten. The other places where the streams and the
//! text disagree are constants of the arithmetic, and each is written down
//! where it is used.
//!
//! Formats are given as Qn, a signed word whose value is its integer divided
//! by 2^n.

/// `L1`: the first stage of the LSF quantizer, 128 ten-dimensional entries,
/// Q13 radians.
pub(super) const FIRST_STAGE: [[i16; 10]; 128] = [
    [
        1486, 2168, 3751, 9074, 12134, 13944, 17983, 19173, 21190, 21820,
    ],
    [
        1730, 2640, 3450, 4870, 6126, 7876, 15644, 17817, 20294, 21902,
    ],
    [
        1568, 2256, 3088, 4874, 11063, 13393, 18307, 19293, 21109, 21741,
    ],
    [
        1733, 2512, 3357, 4708, 6977, 10296, 17024, 17956, 19145, 20350,
    ],
    [
        1744, 2436, 3308, 8731, 10432, 12007, 15614, 16639, 21359, 21913,
    ],
    [
        1786, 2369, 3372, 4521, 6795, 12963, 17674, 18988, 20855, 21640,
    ],
    [
        1631, 2433, 3361, 6328, 10709, 12013, 13277, 13904, 19441, 21088,
    ],
    [
        1489, 2364, 3291, 6250, 9227, 10403, 13843, 15278, 17721, 21451,
    ],
    [
        1869, 2533, 3475, 4365, 9152, 14513, 15908, 17022, 20611, 21411,
    ],
    [
        2070, 3025, 4333, 5854, 7805, 9231, 10597, 16047, 20109, 21834,
    ],
    [
        1910, 2673, 3419, 4261, 11168, 15111, 16577, 17591, 19310, 20265,
    ],
    [
        1141, 1815, 2624, 4623, 6495, 9588, 13968, 16428, 19351, 21286,
    ],
    [
        2192, 3171, 4707, 5808, 10904, 12500, 14162, 15664, 21124, 21789,
    ],
    [
        1286, 1907, 2548, 3453, 9574, 11964, 15978, 17344, 19691, 22495,
    ],
    [
        1921, 2720, 4604, 6684, 11503, 12992, 14350, 15262, 16997, 20791,
    ],
    [
        2052, 2759, 3897, 5246, 6638, 10267, 15834, 16814, 18149, 21675,
    ],
    [
        1798, 2497, 5617, 11449, 13189, 14711, 17050, 18195, 20307, 21182,
    ],
    [
        1009, 1647, 2889, 5709, 9541, 12354, 15231, 18494, 20966, 22033,
    ],
    [
        3016, 3794, 5406, 7469, 12488, 13984, 15328, 16334, 19952, 20791,
    ],
    [
        2203, 3040, 3796, 5442, 11987, 13512, 14931, 16370, 17856, 18803,
    ],
    [
        2912, 4292, 7988, 9572, 11562, 13244, 14556, 16529, 20004, 21073,
    ],
    [
        2861, 3607, 5923, 7034, 9234, 12054, 13729, 18056, 20262, 20974,
    ],
    [
        3069, 4311, 5967, 7367, 11482, 12699, 14309, 16233, 18333, 19172,
    ],
    [
        2434, 3661, 4866, 5798, 10383, 11722, 13049, 15668, 18862, 19831,
    ],
    [
        2020, 2605, 3860, 9241, 13275, 14644, 16010, 17099, 19268, 20251,
    ],
    [
        1877, 2809, 3590, 4707, 11056, 12441, 15622, 17168, 18761, 19907,
    ],
    [
        2107, 2873, 3673, 5799, 13579, 14687, 15938, 17077, 18890, 19831,
    ],
    [
        1612, 2284, 2944, 3572, 8219, 13959, 15924, 17239, 18592, 20117,
    ],
    [
        2420, 3156, 6542, 10215, 12061, 13534, 15305, 16452, 18717, 19880,
    ],
    [
        1667, 2612, 3534, 5237, 10513, 11696, 12940, 16798, 18058, 19378,
    ],
    [
        2388, 3017, 4839, 9333, 11413, 12730, 15024, 16248, 17449, 18677,
    ],
    [
        1875, 2786, 4231, 6320, 8694, 10149, 11785, 17013, 18608, 19960,
    ],
    [
        679, 1411, 4654, 8006, 11446, 13249, 15763, 18127, 20361, 21567,
    ],
    [
        1838, 2596, 3578, 4608, 5650, 11274, 14355, 15886, 20579, 21754,
    ],
    [
        1303, 1955, 2395, 3322, 12023, 13764, 15883, 18077, 20180, 21232,
    ],
    [
        1438, 2102, 2663, 3462, 8328, 10362, 13763, 17248, 19732, 22344,
    ],
    [
        860, 1904, 6098, 7775, 9815, 12007, 14821, 16709, 19787, 21132,
    ],
    [
        1673, 2723, 3704, 6125, 7668, 9447, 13683, 14443, 20538, 21731,
    ],
    [
        1246, 1849, 2902, 4508, 7221, 12710, 14835, 16314, 19335, 22720,
    ],
    [
        1525, 2260, 3862, 5659, 7342, 11748, 13370, 14442, 18044, 21334,
    ],
    [
        1196, 1846, 3104, 7063, 10972, 12905, 14814, 17037, 19922, 22636,
    ],
    [
        2147, 3106, 4475, 6511, 8227, 9765, 10984, 12161, 18971, 21300,
    ],
    [
        1585, 2405, 2994, 4036, 11481, 13177, 14519, 15431, 19967, 21275,
    ],
    [
        1778, 2688, 3614, 4680, 9465, 11064, 12473, 16320, 19742, 20800,
    ],
    [
        1862, 2586, 3492, 6719, 11708, 13012, 14364, 16128, 19610, 20425,
    ],
    [
        1395, 2156, 2669, 3386, 10607, 12125, 13614, 16705, 18976, 21367,
    ],
    [
        1444, 2117, 3286, 6233, 9423, 12981, 14998, 15853, 17188, 21857,
    ],
    [
        2004, 2895, 3783, 4897, 6168, 7297, 12609, 16445, 19297, 21465,
    ],
    [
        1495, 2863, 6360, 8100, 11399, 14271, 15902, 17711, 20479, 22061,
    ],
    [
        2484, 3114, 5718, 7097, 8400, 12616, 14073, 14847, 20535, 21396,
    ],
    [
        2424, 3277, 5296, 6284, 11290, 12903, 16022, 17508, 19333, 20283,
    ],
    [
        2565, 3778, 5360, 6989, 8782, 10428, 14390, 15742, 17770, 21734,
    ],
    [
        2727, 3384, 6613, 9254, 10542, 12236, 14651, 15687, 20074, 21102,
    ],
    [
        1916, 2953, 6274, 8088, 9710, 10925, 12392, 16434, 20010, 21183,
    ],
    [
        3384, 4366, 5349, 7667, 11180, 12605, 13921, 15324, 19901, 20754,
    ],
    [
        3075, 4283, 5951, 7619, 9604, 11010, 12384, 14006, 20658, 21497,
    ],
    [
        1751, 2455, 5147, 9966, 11621, 13176, 14739, 16470, 20788, 21756,
    ],
    [
        1442, 2188, 3330, 6813, 8929, 12135, 14476, 15306, 19635, 20544,
    ],
    [
        2294, 2895, 4070, 8035, 12233, 13416, 14762, 17367, 18952, 19688,
    ],
    [
        1937, 2659, 4602, 6697, 9071, 12863, 14197, 15230, 16047, 18877,
    ],
    [
        2071, 2663, 4216, 9445, 10887, 12292, 13949, 14909, 19236, 20341,
    ],
    [
        1740, 2491, 3488, 8138, 9656, 11153, 13206, 14688, 20896, 21907,
    ],
    [
        2199, 2881, 4675, 8527, 10051, 11408, 14435, 15463, 17190, 20597,
    ],
    [
        1943, 2988, 4177, 6039, 7478, 8536, 14181, 15551, 17622, 21579,
    ],
    [
        1825, 3175, 7062, 9818, 12824, 15450, 18330, 19856, 21830, 22412,
    ],
    [
        2464, 3046, 4822, 5977, 7696, 15398, 16730, 17646, 20588, 21320,
    ],
    [
        2550, 3393, 5305, 6920, 10235, 14083, 18143, 19195, 20681, 21336,
    ],
    [
        3003, 3799, 5321, 6437, 7919, 11643, 15810, 16846, 18119, 18980,
    ],
    [
        3455, 4157, 6838, 8199, 9877, 12314, 15905, 16826, 19949, 20892,
    ],
    [
        3052, 3769, 4891, 5810, 6977, 10126, 14788, 15990, 19773, 20904,
    ],
    [
        3671, 4356, 5827, 6997, 8460, 12084, 14154, 14939, 19247, 20423,
    ],
    [
        2716, 3684, 5246, 6686, 8463, 10001, 12394, 14131, 16150, 19776,
    ],
    [
        1945, 2638, 4130, 7995, 14338, 15576, 17057, 18206, 20225, 20997,
    ],
    [
        2304, 2928, 4122, 4824, 5640, 13139, 15825, 16938, 20108, 21054,
    ],
    [
        1800, 2516, 3350, 5219, 13406, 15948, 17618, 18540, 20531, 21252,
    ],
    [
        1436, 2224, 2753, 4546, 9657, 11245, 15177, 16317, 17489, 19135,
    ],
    [
        2319, 2899, 4980, 6936, 8404, 13489, 15554, 16281, 20270, 20911,
    ],
    [
        2187, 2919, 4610, 5875, 7390, 12556, 14033, 16794, 20998, 21769,
    ],
    [
        2235, 2923, 5121, 6259, 8099, 13589, 15340, 16340, 17927, 20159,
    ],
    [
        1765, 2638, 3751, 5730, 7883, 10108, 13633, 15419, 16808, 18574,
    ],
    [
        3460, 5741, 9596, 11742, 14413, 16080, 18173, 19090, 20845, 21601,
    ],
    [
        3735, 4426, 6199, 7363, 9250, 14489, 16035, 17026, 19873, 20876,
    ],
    [
        3521, 4778, 6887, 8680, 12717, 14322, 15950, 18050, 20166, 21145,
    ],
    [
        2141, 2968, 6865, 8051, 10010, 13159, 14813, 15861, 17528, 18655,
    ],
    [
        4148, 6128, 9028, 10871, 12686, 14005, 15976, 17208, 19587, 20595,
    ],
    [
        4403, 5367, 6634, 8371, 10163, 11599, 14963, 16331, 17982, 18768,
    ],
    [
        4091, 5386, 6852, 8770, 11563, 13290, 15728, 16930, 19056, 20102,
    ],
    [
        2746, 3625, 5299, 7504, 10262, 11432, 13172, 15490, 16875, 17514,
    ],
    [
        2248, 3556, 8539, 10590, 12665, 14696, 16515, 17824, 20268, 21247,
    ],
    [
        1279, 1960, 3920, 7793, 10153, 14753, 16646, 18139, 20679, 21466,
    ],
    [
        2440, 3475, 6737, 8654, 12190, 14588, 17119, 17925, 19110, 19979,
    ],
    [
        1879, 2514, 4497, 7572, 10017, 14948, 16141, 16897, 18397, 19376,
    ],
    [
        2804, 3688, 7490, 10086, 11218, 12711, 16307, 17470, 20077, 21126,
    ],
    [
        2023, 2682, 3873, 8268, 10255, 11645, 15187, 17102, 18965, 19788,
    ],
    [
        2823, 3605, 5815, 8595, 10085, 11469, 16568, 17462, 18754, 19876,
    ],
    [
        2851, 3681, 5280, 7648, 9173, 10338, 14961, 16148, 17559, 18474,
    ],
    [
        1348, 2645, 5826, 8785, 10620, 12831, 16255, 18319, 21133, 22586,
    ],
    [
        2141, 3036, 4293, 6082, 7593, 10629, 17158, 18033, 21466, 22084,
    ],
    [
        1608, 2375, 3384, 6878, 9970, 11227, 16928, 17650, 20185, 21120,
    ],
    [
        2774, 3616, 5014, 6557, 7788, 8959, 17068, 18302, 19537, 20542,
    ],
    [
        1934, 4813, 6204, 7212, 8979, 11665, 15989, 17811, 20426, 21703,
    ],
    [
        2288, 3507, 5037, 6841, 8278, 9638, 15066, 16481, 21653, 22214,
    ],
    [
        2951, 3771, 4878, 7578, 9016, 10298, 14490, 15242, 20223, 20990,
    ],
    [
        3256, 4791, 6601, 7521, 8644, 9707, 13398, 16078, 19102, 20249,
    ],
    [
        1827, 2614, 3486, 6039, 12149, 13823, 16191, 17282, 21423, 22041,
    ],
    [
        1000, 1704, 3002, 6335, 8471, 10500, 14878, 16979, 20026, 22427,
    ],
    [
        1646, 2286, 3109, 7245, 11493, 12791, 16824, 17667, 18981, 20222,
    ],
    [
        1708, 2501, 3315, 6737, 8729, 9924, 16089, 17097, 18374, 19917,
    ],
    [
        2623, 3510, 4478, 5645, 9862, 11115, 15219, 18067, 19583, 20382,
    ],
    [
        2518, 3434, 4728, 6388, 8082, 9285, 13162, 18383, 19819, 20552,
    ],
    [
        1726, 2383, 4090, 6303, 7805, 12845, 14612, 17608, 19269, 20181,
    ],
    [
        2860, 3735, 4838, 6044, 7254, 8402, 14031, 16381, 18037, 19410,
    ],
    [
        4247, 5993, 7952, 9792, 12342, 14653, 17527, 18774, 20831, 21699,
    ],
    [
        3502, 4051, 5680, 6805, 8146, 11945, 16649, 17444, 20390, 21564,
    ],
    [
        3151, 4893, 5899, 7198, 11418, 13073, 15124, 17673, 20520, 21861,
    ],
    [
        3960, 4848, 5926, 7259, 8811, 10529, 15661, 16560, 18196, 20183,
    ],
    [
        4499, 6604, 8036, 9251, 10804, 12627, 15880, 17512, 20020, 21046,
    ],
    [
        4251, 5541, 6654, 8318, 9900, 11686, 15100, 17093, 20572, 21687,
    ],
    [
        3769, 5327, 7865, 9360, 10684, 11818, 13660, 15366, 18733, 19882,
    ],
    [
        3083, 3969, 6248, 8121, 9798, 10994, 12393, 13686, 17888, 19105,
    ],
    [
        2731, 4670, 7063, 9201, 11346, 13735, 16875, 18797, 20787, 22360,
    ],
    [
        1187, 2227, 4737, 7214, 9622, 12633, 15404, 17968, 20262, 23533,
    ],
    [
        1911, 2477, 3915, 10098, 11616, 12955, 16223, 17138, 19270, 20729,
    ],
    [
        1764, 2519, 3887, 6944, 9150, 12590, 16258, 16984, 17924, 18435,
    ],
    [
        1400, 3674, 7131, 8718, 10688, 12508, 15708, 17711, 19720, 21068,
    ],
    [
        2322, 3073, 4287, 8108, 9407, 10628, 15862, 16693, 19714, 21474,
    ],
    [
        2630, 3339, 4758, 8360, 10274, 11333, 12880, 17374, 19221, 19936,
    ],
    [
        1721, 2577, 5553, 7195, 8651, 10686, 15069, 16953, 18703, 19929,
    ],
];

/// `L2`: the second stage for the lower five coefficients, 32 entries, Q13.
pub(super) const SECOND_STAGE_LOW: [[i16; 5]; 32] = [
    [-435, -815, -742, 1033, -518],
    [-833, -891, 463, -8, -1251],
    [-1021, 231, -306, 321, -220],
    [57, -198, -339, -33, -1468],
    [171, -350, 294, 1660, 453],
    [-701, -842, -58, 950, 892],
    [584, 31, -289, 356, -333],
    [-109, -808, 231, 77, -87],
    [-859, 1236, 550, 854, 714],
    [-877, -954, -1248, -299, 212],
    [-77, 344, -620, 763, 413],
    [-314, -307, -256, -1260, -429],
    [711, 693, 521, 650, 1305],
    [-112, -271, -500, 946, 1733],
    [575, -10, -468, -199, 1101],
    [145, -285, -1280, -398, 36],
    [-1133, -835, 1350, 1284, -95],
    [-1459, -1237, 416, -213, 466],
    [-15, 66, 468, 1019, -748],
    [-338, 148, 1445, 75, -760],
    [389, 239, 1568, 981, 113],
    [-312, -98, 949, 31, 1104],
    [1127, 584, 835, 277, -1159],
    [539, -114, 856, -493, 223],
    [2197, 2337, 1268, 670, 304],
    [-1596, 550, 801, -456, -56],
    [1154, 593, -77, 1237, -31],
    [397, 558, 203, -797, -919],
    [334, 1475, 632, -80, 48],
    [-545, -330, -429, -680, 1133],
    [1320, 827, -398, -576, 341],
    [-163, 674, -11, -886, 531],
];

/// `L3`: the second stage for the upper five coefficients, 32 entries, Q13.
pub(super) const SECOND_STAGE_HIGH: [[i16; 5]; 32] = [
    [582, -1201, 829, 86, 385],
    [1450, 72, -231, 864, 661],
    [-163, -526, -754, -1633, 267],
    [573, 796, -169, -631, 816],
    [519, 291, 159, -640, -1296],
    [1549, 715, 527, -714, -193],
    [-457, 612, -283, -1381, -741],
    [-344, 1341, 1087, -654, -569],
    [-543, -1752, -195, -98, -276],
    [-235, -728, 949, 1517, 895],
    [502, -362, -960, -483, 1386],
    [450, -466, -108, 1010, 2223],
    [-28, -378, 744, -1005, 240],
    [271, -15, 909, -259, 1688],
    [-1011, 581, -53, -747, 878],
    [-498, -1377, 18, -444, 1483],
    [1015, -222, 443, 372, -354],
    [669, 659, 1640, 932, 534],
    [1385, -182, -907, -721, -262],
    [569, 1247, 337, 416, -121],
    [369, -1003, -507, -587, -904],
    [72, -141, 1465, 63, -785],
    [208, 301, -882, 117, -404],
    [-912, 623, -76, 276, -440],
    [-267, -525, 140, 882, -139],
    [-697, 865, 1060, 413, 446],
    [581, -1037, -895, 669, 297],
    [3, 692, -292, 1050, 782],
    [-1061, -484, 362, -597, -852],
    [-1182, -744, 1340, 262, 63],
    [-774, -483, -1247, -70, 98],
    [-1125, -265, -242, 724, 934],
];

/// `p̂(i,k)`: the two switched fourth-order MA predictors of equation 20,
/// selected by `L0`; for each, four frames back by ten coefficients, Q15.
pub(super) const MA_PREDICTOR: [[[i16; 10]; 4]; 2] = [
    [
        [8421, 9109, 9175, 8965, 9034, 9057, 8765, 8775, 9106, 8673],
        [7018, 7189, 7638, 7307, 7444, 7379, 7038, 6956, 6930, 6868],
        [5472, 4990, 5134, 5177, 5246, 5141, 5206, 5095, 4830, 5147],
        [4056, 3031, 2614, 3024, 2916, 2713, 3309, 3237, 2857, 3473],
    ],
    [
        [7733, 7880, 8188, 8175, 8247, 8490, 8637, 8601, 8359, 7569],
        [4210, 3031, 2552, 3473, 3876, 3853, 4184, 4154, 3909, 3968],
        [3214, 1930, 1313, 2143, 2493, 2385, 2755, 2706, 2542, 2919],
        [3024, 1592, 940, 1631, 1723, 1579, 2034, 2084, 1913, 2601],
    ],
];

/// `1 − Σ p̂(i,k)`: the weight equation 20 gives the current frame's
/// quantizer output, per predictor and coefficient, Q15.
pub(super) const MA_CURRENT_WEIGHT: [[i16; 10]; 2] = [
    [7798, 8447, 8205, 8293, 8126, 8477, 8447, 8703, 9043, 8604],
    [
        14585, 18333, 19772, 17344, 16426, 16459, 15155, 15220, 16043, 15708,
    ],
];

/// Its reciprocal, which equation 92 divides by, Q12.
pub(super) const MA_CURRENT_WEIGHT_INVERSE: [[i16; 10]; 2] = [
    [
        17210, 15888, 16357, 16183, 16516, 15833, 15888, 15421, 14840, 15597,
    ],
    [9202, 7320, 6788, 7738, 8170, 8154, 8856, 8818, 8366, 8544],
];

/// `l̂` before the first frame: `iπ/11` for `i = 1..10` (Table 9), Q13,
/// truncated.
pub(super) const INITIAL_LSF: [i16; 10] = [
    2339, 4679, 7018, 9358, 11698, 14037, 16377, 18717, 21056, 23396,
];

/// `q̂` before the first frame, the cosines the first subframe is
/// interpolated from, Q15. Not Table 9's `cos(iπ/11)`: see the module
/// documentation.
pub(super) const INITIAL_LSP: [i16; 10] = [
    30_000, 26_000, 21_000, 15_000, 8_000, 0, -8_000, -15_000, -21_000, -26_000,
];

/// `b30`: the filter that interpolates the past excitation at a third of a
/// sample (§3.7.1), `b30(0)` to `b30(30)`, Q15.
pub(super) const INTERPOLATION_B30: [i16; 31] = [
    29443, 25207, 14701, 3143, -4402, -5850, -2783, 1211, 3130, 2259, 0, -1652, -1666, -464, 756,
    1099, 550, -245, -634, -451, 0, 308, 296, 78, -120, -165, -79, 34, 91, 70, 0,
];

/// `[b1 b2 b3 b4] = [0.68 0.58 0.34 0.19]`, equation 69, Q13.
pub(super) const GAIN_PREDICTOR: [i16; 4] = [5571, 4751, 2785, 1556];

/// `GA`: the first stage of the gain quantizer. Each row is the pitch gain
/// (Q14) and the fixed-codebook gain correction (Q13).
pub(super) const GA: [[i16; 2]; 8] = [
    [1, 1516],
    [1551, 2425],
    [1831, 5022],
    [57, 5404],
    [1921, 9291],
    [3242, 9949],
    [356, 14756],
    [2678, 27162],
];

/// `GB`: the second stage, in the same formats.
pub(super) const GB: [[i16; 2]; 16] = [
    [826, 2005],
    [1994, 0],
    [5142, 592],
    [6160, 2395],
    [8091, 4861],
    [9120, 525],
    [10573, 2966],
    [11569, 1196],
    [13260, 3256],
    [14194, 1630],
    [15132, 4914],
    [15161, 14276],
    [15434, 237],
    [16112, 3392],
    [17299, 1861],
    [18973, 5935],
];

/// The row of `GA` a received `GA` codeword names (§3.9.3: "the codebook
/// indices are mapped").
pub(super) const GA_ROW: [u8; 8] = [5, 1, 7, 4, 2, 0, 6, 3];

/// The row of `GB` a received `GB` codeword names.
pub(super) const GB_ROW: [u8; 16] = [2, 14, 3, 13, 0, 15, 1, 12, 6, 10, 7, 9, 4, 11, 5, 8];

/// `cos(iπ/64)` for `i = 0..63`, Q15, the first entry held one below the
/// top of the word.
pub(super) const COSINE: [i16; 64] = [
    32767, 32729, 32610, 32413, 32138, 31786, 31357, 30853, 30274, 29622, 28899, 28106, 27246,
    26320, 25330, 24279, 23170, 22006, 20788, 19520, 18205, 16846, 15447, 14010, 12540, 11039,
    9512, 7962, 6393, 4808, 3212, 1608, 0, -1608, -3212, -4808, -6393, -7962, -9512, -11039,
    -12540, -14010, -15447, -16846, -18205, -19520, -20788, -22006, -23170, -24279, -25330, -26320,
    -27246, -28106, -28899, -29622, -30274, -30853, -31357, -31786, -32138, -32413, -32610, -32729,
];

/// The step from each entry of [`COSINE`] to the next, sixteen times over,
/// so that a Q8 position inside the segment scales it with a shift by twelve.
pub(super) const COSINE_SLOPE: [i16; 64] = [
    -632, -1893, -3150, -4399, -5638, -6863, -8072, -9261, -10428, -11570, -12684, -13767, -14817,
    -15832, -16808, -17744, -18637, -19486, -20287, -21039, -21741, -22390, -22986, -23526, -24009,
    -24435, -24801, -25108, -25354, -25540, -25664, -25726, -25726, -25664, -25540, -25354, -25108,
    -24801, -24435, -24009, -23526, -22986, -22390, -21741, -21039, -20287, -19486, -18637, -17744,
    -16808, -15832, -14817, -13767, -12684, -11570, -10428, -9261, -8072, -6863, -5638, -4399,
    -3150, -1893, -632,
];

/// `2^(i/32)` for `i = 0..32`, Q14, the last entry held one below the top.
pub(super) const POWER_OF_TWO: [i16; 33] = [
    16384, 16743, 17109, 17484, 17867, 18258, 18658, 19066, 19484, 19911, 20347, 20792, 21247,
    21713, 22188, 22674, 23170, 23678, 24196, 24726, 25268, 25821, 26386, 26964, 27554, 28158,
    28774, 29405, 30048, 30706, 31379, 32066, 32767,
];

/// `log2(1 + i/32)` for `i = 0..32`, Q15.
pub(super) const LOG2: [i16; 33] = [
    0, 1455, 2866, 4236, 5568, 6863, 8124, 9352, 10549, 11716, 12855, 13967, 15054, 16117, 17156,
    18172, 19167, 20142, 21097, 22033, 22951, 23852, 24735, 25603, 26455, 27291, 28113, 28922,
    29716, 30497, 31266, 32023, 32767,
];

/// `1/√(1 + i/16)` for `i = 0..48`, Q15: the inverse square root of a
/// mantissa between one and four.
pub(super) const INVERSE_SQRT: [i16; 49] = [
    32767, 31790, 30894, 30070, 29309, 28602, 27945, 27330, 26755, 26214, 25705, 25225, 24770,
    24339, 23930, 23541, 23170, 22817, 22479, 22155, 21845, 21548, 21263, 20988, 20724, 20470,
    20225, 19988, 19760, 19539, 19326, 19119, 18919, 18725, 18536, 18354, 18176, 18004, 17837,
    17674, 17515, 17361, 17211, 17064, 16921, 16782, 16646, 16514, 16384,
];

/// Equation 91's numerator, `0.93980581 − 1.8795834 z⁻¹ + 0.93980581 z⁻²`,
/// Q13.
pub(super) const OUTPUT_HIGH_PASS_ZEROS: [i16; 3] = [7699, -15398, 7699];

/// Equation 91's denominator with the signs a recursion adds it with:
/// `y(n) += 1.9330735 y(n−1) − 0.93589199 y(n−2)`, Q13. The leading one is
/// carried for completeness and not used.
pub(super) const OUTPUT_HIGH_PASS_POLES: [i16; 3] = [8192, 15836, -7667];

/// Equation 1's numerator, `0.46363718 − 0.92724705 z⁻¹ + 0.46363718 z⁻²`:
/// the 140 Hz high-pass with the input's halving folded in, Q12.
pub(super) const INPUT_HIGH_PASS_ZEROS: [i16; 3] = [1899, -3798, 1899];

/// Equation 1's denominator, signed for the recursion:
/// `y(n) += 1.9059465 y(n−1) − 0.9114024 y(n−2)`, Q12. The leading one is
/// not used.
pub(super) const INPUT_HIGH_PASS_POLES: [i16; 3] = [4096, 7807, -3733];

/// `wlp(n)` of equation 3, the LP analysis window, `n = 0..239`: half a
/// Hamming window over 200 samples, then a quarter cosine over 40, Q15.
pub(super) const LP_WINDOW: [i16; 240] = [
    2621, 2623, 2629, 2638, 2651, 2668, 2689, 2713, 2741, 2772, 2808, 2847, 2890, 2936, 2986, 3040,
    3097, 3158, 3223, 3291, 3363, 3438, 3517, 3599, 3685, 3774, 3867, 3963, 4063, 4166, 4272, 4382,
    4495, 4611, 4731, 4853, 4979, 5108, 5240, 5376, 5514, 5655, 5800, 5947, 6097, 6250, 6406, 6565,
    6726, 6890, 7057, 7227, 7399, 7573, 7750, 7930, 8112, 8296, 8483, 8672, 8863, 9057, 9252, 9450,
    9650, 9852, 10055, 10261, 10468, 10677, 10888, 11101, 11315, 11531, 11748, 11967, 12187, 12409,
    12632, 12856, 13082, 13308, 13536, 13764, 13994, 14225, 14456, 14688, 14921, 15155, 15389,
    15624, 15859, 16095, 16331, 16568, 16805, 17042, 17279, 17516, 17754, 17991, 18228, 18465,
    18702, 18939, 19175, 19411, 19647, 19882, 20117, 20350, 20584, 20816, 21048, 21279, 21509,
    21738, 21967, 22194, 22420, 22644, 22868, 23090, 23311, 23531, 23749, 23965, 24181, 24394,
    24606, 24816, 25024, 25231, 25435, 25638, 25839, 26037, 26234, 26428, 26621, 26811, 26999,
    27184, 27368, 27548, 27727, 27903, 28076, 28247, 28415, 28581, 28743, 28903, 29061, 29215,
    29367, 29515, 29661, 29804, 29944, 30081, 30214, 30345, 30472, 30597, 30718, 30836, 30950,
    31062, 31170, 31274, 31376, 31474, 31568, 31659, 31747, 31831, 31911, 31988, 32062, 32132,
    32198, 32261, 32320, 32376, 32428, 32476, 32521, 32561, 32599, 32632, 32662, 32688, 32711,
    32729, 32744, 32755, 32763, 32767, 32767, 32741, 32665, 32537, 32359, 32129, 31850, 31521,
    31143, 30716, 30242, 29720, 29151, 28538, 27879, 27177, 26433, 25647, 24821, 23957, 23055,
    22117, 21145, 20139, 19102, 18036, 16941, 15820, 14674, 13505, 12315, 11106, 9879, 8637, 7381,
    6114, 4838, 3554, 2264, 971,
];

/// `wlag(k)` of equation 6 for `k = 1..12`, divided by the white-noise
/// correction 1.0001 of equation 7: multiplying `r(k)` by this and leaving
/// `r(0)` alone is the same filter as the text's, scaled by a constant the
/// Levinson-Durbin recursion does not see. A Q31 value split into its upper
/// sixteen bits and the fifteen below them, as `arith::Split` holds it. The
/// LP analysis reads the first ten; Annex B's voice activity detector reads
/// all twelve (B.3.1: `q = 12`).
pub(super) const LAG_WINDOW: [(i16, i16); 12] = [
    (32728, 11904),
    (32619, 17280),
    (32438, 30720),
    (32187, 25856),
    (31867, 24192),
    (31480, 28992),
    (31029, 24384),
    (30517, 7360),
    (29946, 19520),
    (29321, 14784),
    (28645, 22092),
    (27923, 12924),
];

/// The points the LP → LSP conversion looks for sign changes between
/// (A.3.2.3): `cos(jπ/50)` for `j = 0..50`, Q15, truncated toward zero, with
/// the two ends held at ±32760 rather than ±1.
pub(super) const GRID: [i16; 51] = [
    32760, 32703, 32509, 32187, 31738, 31164, 30466, 29649, 28714, 27666, 26509, 25248, 23886,
    22431, 20887, 19260, 17557, 15786, 13951, 12062, 10125, 8149, 6140, 4106, 2057, 0, -2057,
    -4106, -6140, -8149, -10125, -12062, -13951, -15786, -17557, -19260, -20887, -22431, -23886,
    -25248, -26509, -27666, -28714, -29649, -30466, -31164, -31738, -32187, -32509, -32703, -32760,
];

/// The inverse of each segment's slope in [`COSINE`], for reading the table
/// backwards: an LSP's distance below an entry, times this, is its distance
/// along the segment in the units of the LSF's table position.
pub(super) const ARCCOS_SLOPE: [i16; 64] = [
    -26887, -8812, -5323, -3813, -2979, -2444, -2081, -1811, -1608, -1450, -1322, -1219, -1132,
    -1059, -998, -946, -901, -861, -827, -797, -772, -750, -730, -713, -699, -687, -677, -668,
    -662, -657, -654, -652, -652, -654, -657, -662, -668, -677, -687, -699, -713, -730, -750, -772,
    -797, -827, -861, -901, -946, -998, -1059, -1132, -1219, -1322, -1450, -1608, -1811, -2081,
    -2444, -2979, -3813, -5323, -8812, -26887,
];

/// The `GA` codeword sent for each row of [`GA`]: the inverse of [`GA_ROW`].
pub(super) const GA_CODEWORD: [u8; 8] = [5, 1, 4, 7, 3, 0, 6, 2];

/// The `GB` codeword sent for each row of [`GB`]: the inverse of [`GB_ROW`].
pub(super) const GB_CODEWORD: [u8; 16] = [4, 6, 0, 2, 12, 14, 8, 10, 15, 11, 9, 13, 7, 3, 1, 5];

/// The gain preselection's two slopes (§3.9.2), which carry the optimum
/// gains into coordinates along the two codebooks: `31.134575` in Q10 and
/// `0.481389` in Q16.
pub(super) const PRESELECTION_SLOPES: [i16; 2] = [31881, 31548];

/// Its two offsets, in thirty-two bits: `1.612322` in Q30 and `0.053056` in
/// Q35.
pub(super) const PRESELECTION_OFFSETS: [i32; 2] = [1_731_217_536, 1_822_990_272];

/// Where along the first line the four clusters of four neighbouring `GA`
/// rows begin, Q14.
pub(super) const GA_THRESHOLDS: [i16; 4] = [10808, 12374, 19778, 32567];

/// Where along the second the eight clusters of eight neighbouring `GB`
/// rows begin, Q15.
pub(super) const GB_THRESHOLDS: [i16; 8] = [14087, 16188, 20274, 21321, 23525, 25232, 27873, 30542];

/// The MA predictors of a SID frame's LSF quantizer (B.4.2.2, item 1): the
/// first is the speech quantizer's first, and the second is equation B.18's
/// mixture of the speech quantizer's two, `0.6 p̂1 + 0.4 p̂2`, Q15. The
/// mixture is formed with 0.6 and 0.4 as the Q15 values below them and the
/// upper half of the doubled sum kept (the test at the end works it out);
/// rounded instead, the Annex B streams do not decode.
pub(super) const NOISE_MA_PREDICTOR: [[[i16; 10]; 4]; 2] = [
    MA_PREDICTOR[0],
    [
        [8145, 8617, 8779, 8648, 8718, 8829, 8713, 8705, 8806, 8231],
        [5894, 5525, 5603, 5773, 6016, 5968, 5896, 5835, 5721, 5707],
        [4568, 3765, 3605, 3963, 4144, 4038, 4225, 4139, 3914, 4255],
        [3643, 2455, 1944, 2466, 2438, 2259, 2798, 2775, 2479, 3124],
    ],
];

/// `1 − Σ p̂(i,k)` for the two predictors of [`NOISE_MA_PREDICTOR`], Q15.
pub(super) const NOISE_MA_CURRENT_WEIGHT: [[i16; 10]; 2] = [
    [7798, 8447, 8205, 8293, 8126, 8477, 8447, 8703, 9043, 8604],
    [
        10514, 12402, 12833, 11914, 11447, 11670, 11132, 11311, 11844, 11447,
    ],
];

/// Its reciprocal, Q12.
pub(super) const NOISE_MA_CURRENT_WEIGHT_INVERSE: [[i16; 10]; 2] = [
    [
        17210, 15888, 16357, 16183, 16516, 15833, 15888, 15421, 14840, 15597,
    ],
    [
        12764, 10821, 10458, 11264, 11724, 11500, 12056, 11865, 11331, 11724,
    ],
];

/// The part of `L1` a SID frame's first stage uses (B.4.2.2, item 2): the
/// row of [`FIRST_STAGE`] each of the thirty-two first-stage indices names.
pub(super) const SID_FIRST_STAGE_ROWS: [u8; 32] = [
    96, 52, 20, 54, 86, 114, 82, 68, 36, 121, 48, 92, 18, 120, 94, 124, 50, 125, 4, 100, 28, 76,
    12, 117, 81, 22, 90, 116, 127, 21, 108, 66,
];

/// What the first stage's squared error is scaled by for each of the two
/// noise predictors before the candidates are compared, Q15: about four
/// times the mean square of the predictor's current-frame weight, so that
/// errors in the two predictors' targets are compared in the units of the
/// LSFs they would produce.
pub(super) const SID_FIRST_STAGE_SCALE: [i16; 2] = [8644, 16572];

/// The part of `L2` and `L3` its second stage uses (item 3): for each of
/// the sixteen second-stage indices, the row of [`SECOND_STAGE_LOW`] that
/// gives the lower five coefficients and the row of [`SECOND_STAGE_HIGH`]
/// that gives the upper five.
pub(super) const SID_SECOND_STAGE_ROWS: [[u8; 16]; 2] = [
    [31, 21, 9, 3, 10, 2, 19, 26, 4, 3, 11, 29, 15, 27, 21, 12],
    [16, 1, 0, 0, 8, 25, 22, 20, 19, 23, 20, 31, 4, 31, 20, 31],
];

/// The thirty-two levels of B.4.2.1's energy quantizer as the gains of the
/// comfort noise they describe: `√` of the energy, Q3. The levels are −12 dB,
/// −4 to 16 dB in steps of 4, and 18 to 66 dB in steps of 2.
pub(super) const SID_GAINS: [i16; 32] = [
    2, 5, 8, 13, 20, 32, 50, 64, 80, 101, 127, 160, 201, 253, 318, 401, 505, 635, 800, 1007, 1268,
    1596, 2010, 2530, 3185, 4009, 5048, 6355, 8000, 10071, 12679, 15962,
];

/// B.3.1.3's low-band filter as the voice activity detector uses it: the
/// autocorrelation of its impulse response `h`, lags 0 to 12, so that
/// `hᵀRh` is `c(0) R(0) + 2 Σ c(k) R(k)`, Q15.
pub(super) const LOW_BAND_CORRELATION: [i16; 13] = [
    7869, 7011, 4838, 2299, 321, -660, -782, -484, -164, 3, 39, 21, 4,
];

/// `32/(32 − n)` for `n = 0..32` as a Q15 mantissa and the left shift that
/// scales it back: what turns a sum over the thirty-two frames of B.3.2
/// divided by thirty-two into the average over the `32 − n` of them that
/// were loud enough to count. The last entry, for none of them, is zero.
pub(super) const LOUD_FRAMES_MANTISSA: [i16; 33] = [
    32767, 16913, 17476, 18079, 18725, 19418, 20165, 20972, 21845, 22795, 23831, 24966, 26214,
    27594, 29127, 30840, 32767, 17476, 18725, 20165, 21845, 23831, 26214, 29127, 32767, 18725,
    21845, 26214, 32767, 21845, 32767, 32767, 0,
];

/// The shifts that go with [`LOUD_FRAMES_MANTISSA`].
pub(super) const LOUD_FRAMES_SHIFT: [u8; 33] = [
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 5,
    0,
];

/// Equation B.15's factor `αw / (kE · Ncur · 80)`, Q15, for the energy of an
/// erased first SID frame (entry 0, one frame of excitation) and for sums of
/// one and of two residual energies (entries 1 and 2).
pub(super) const SID_ENERGY_FACTOR: [i16; 3] = [410, 26, 13];

/// The bits of headroom the sum of residual energies is formed with, for
/// the same three cases.
pub(super) const SID_ENERGY_HEADROOM: [i16; 3] = [0, 0, 1];

#[cfg(test)]
mod tests {
    use super::{
        ARCCOS_SLOPE, COSINE, COSINE_SLOPE, FIRST_STAGE, GA, GA_CODEWORD, GA_ROW, GA_THRESHOLDS,
        GAIN_PREDICTOR, GB, GB_CODEWORD, GB_ROW, GB_THRESHOLDS, GRID, INITIAL_LSF, INITIAL_LSP,
        INPUT_HIGH_PASS_POLES, INPUT_HIGH_PASS_ZEROS, INTERPOLATION_B30, INVERSE_SQRT, LAG_WINDOW,
        LOG2, LOUD_FRAMES_MANTISSA, LOUD_FRAMES_SHIFT, LOW_BAND_CORRELATION, LP_WINDOW,
        MA_CURRENT_WEIGHT, MA_CURRENT_WEIGHT_INVERSE, MA_PREDICTOR, NOISE_MA_CURRENT_WEIGHT,
        NOISE_MA_CURRENT_WEIGHT_INVERSE, NOISE_MA_PREDICTOR, OUTPUT_HIGH_PASS_POLES,
        OUTPUT_HIGH_PASS_ZEROS, POWER_OF_TWO, PRESELECTION_OFFSETS, PRESELECTION_SLOPES,
        SECOND_STAGE_HIGH, SECOND_STAGE_LOW, SID_ENERGY_FACTOR, SID_ENERGY_HEADROOM,
        SID_FIRST_STAGE_ROWS, SID_FIRST_STAGE_SCALE, SID_GAINS, SID_SECOND_STAGE_ROWS,
    };
    use core::f64::consts::PI;

    fn nearest(value: f64) -> i32 {
        #[expect(
            clippy::cast_possible_truncation,
            reason = "every value rounded here is a table entry inside i16"
        )]
        let rounded = value.round() as i32;
        rounded
    }

    #[test]
    fn the_codebooks_have_the_sizes_table_1_gives_their_indices() {
        // seven bits, five and five (Table 8)
        assert_eq!(FIRST_STAGE.len(), 1 << 7);
        assert_eq!(SECOND_STAGE_LOW.len(), 1 << 5);
        assert_eq!(SECOND_STAGE_HIGH.len(), 1 << 5);
        // three bits and four
        assert_eq!(GA.len(), 1 << 3);
        assert_eq!(GB.len(), 1 << 4);
        assert_eq!(GA_ROW.len(), GA.len());
        assert_eq!(GB_ROW.len(), GB.len());
        assert_eq!(MA_PREDICTOR.len(), 2, "one bit, L0, selects between them");
        assert_eq!(INTERPOLATION_B30.len(), 31, "b30(0) to b30(30)");
    }

    /// Every first-stage entry is an LSF vector, and §3.2.3 orders LSFs:
    /// `0 < ω1 < ω2 < ... < ω10 < π`.
    #[test]
    fn every_first_stage_entry_is_an_ordered_set_of_frequencies() {
        let pi_q13 = nearest(PI * 8192.0);
        for (row, entry) in FIRST_STAGE.iter().enumerate() {
            assert!(entry.first().is_some_and(|first| *first > 0), "row {row}");
            assert!(
                entry.last().is_some_and(|last| i32::from(*last) < pi_q13),
                "row {row}"
            );
            for pair in entry.windows(2) {
                assert!(pair[0] < pair[1], "row {row} is not in increasing order");
            }
        }
    }

    /// The second stage is a correction, not a spectrum: it is small against
    /// the first and it goes both ways.
    #[test]
    fn the_second_stage_is_a_small_signed_correction() {
        for entry in SECOND_STAGE_LOW.iter().chain(SECOND_STAGE_HIGH.iter()) {
            for value in entry {
                assert!(value.unsigned_abs() < 2_500, "{value}");
            }
        }
        let negatives = SECOND_STAGE_LOW
            .iter()
            .flatten()
            .filter(|value| **value < 0)
            .count();
        assert!(negatives > 40 && negatives < 120, "{negatives}");
    }

    /// The row maps are permutations: every codeword names one row and every
    /// row is named once, or some pair of gains could never be sent.
    #[test]
    fn the_gain_maps_are_permutations() {
        let mut seen = [false; 16];
        for row in GB_ROW {
            let slot = seen.get_mut(usize::from(row)).unwrap();
            assert!(!*slot, "row {row} named twice");
            *slot = true;
        }
        assert!(seen.iter().all(|named| *named));
        let mut seen = [false; 8];
        for row in GA_ROW {
            let slot = seen.get_mut(usize::from(row)).unwrap();
            assert!(!*slot, "row {row} named twice");
            *slot = true;
        }
        assert!(seen.iter().all(|named| *named));
    }

    /// §3.9.2: "The codebook GA contains eight entries in which the second
    /// element ... has, in general, larger values than the first element",
    /// and "the codebook GB contains 16 entries in which each has a bias
    /// towards the first element". The pre-selection depends on both.
    #[test]
    fn the_gain_codebooks_lean_the_way_the_text_says() {
        let ga_second = GA.iter().filter(|row| row[1] > row[0]).count();
        assert!(
            ga_second >= 7,
            "{ga_second} of GA's rows lean to the second"
        );
        let gb_first = GB.iter().filter(|row| row[0] > row[1]).count();
        assert!(gb_first >= 14, "{gb_first} of GB's rows lean to the first");
        // and the first elements of GB are ordered, which the pre-selection
        // by closeness to the pitch gain relies on
        for pair in GB.windows(2) {
            assert!(pair[0][0] <= pair[1][0]);
        }
    }

    /// Each predictor's taps fall off with age, and `1 − Σ p̂` is the weight
    /// the table next to it says, to within the rounding of four products.
    #[test]
    fn the_ma_predictor_and_its_weights_agree() {
        for (predictor, weights) in MA_PREDICTOR.iter().zip(MA_CURRENT_WEIGHT) {
            for coefficient in 0..10 {
                let taps: Vec<i32> = predictor
                    .iter()
                    .map(|row| i32::from(row[coefficient]))
                    .collect();
                for pair in taps.windows(2) {
                    assert!(pair[0] >= pair[1], "an older frame weighs more");
                }
                let rest = 32_768 - taps.iter().sum::<i32>();
                let weight = i32::from(weights[coefficient]);
                assert!((rest - weight).abs() <= 3, "{rest} against {weight}");
            }
        }
        for (weights, inverses) in MA_CURRENT_WEIGHT.iter().zip(MA_CURRENT_WEIGHT_INVERSE) {
            for (weight, inverse) in weights.iter().zip(inverses) {
                let exact = 4096.0 * 32768.0 / f64::from(*weight);
                assert!(
                    (exact - f64::from(inverse)).abs() <= 2.5,
                    "1/{weight} is {exact}, the table says {inverse}"
                );
            }
        }
    }

    /// B.18: the second noise predictor is `0.6 p̂1 + 0.4 p̂2`, formed with
    /// the truncated Q15 weights and the upper half of the doubled sum; the
    /// first is the speech quantizer's first. The current-frame weights
    /// agree with the predictors as the speech ones do, and the inverses are
    /// their reciprocals.
    #[test]
    fn the_noise_predictors_are_equation_b_18() {
        assert_eq!(NOISE_MA_PREDICTOR[0], MA_PREDICTOR[0]);
        for frame in 0..4 {
            for index in 0..10 {
                let first = i32::from(MA_PREDICTOR[0][frame][index]);
                let second = i32::from(MA_PREDICTOR[1][frame][index]);
                let mixed = (2 * (first * 19_660 + second * 13_107)) >> 16;
                assert_eq!(i32::from(NOISE_MA_PREDICTOR[1][frame][index]), mixed);
            }
        }
        assert_eq!(NOISE_MA_CURRENT_WEIGHT[0], MA_CURRENT_WEIGHT[0]);
        assert_eq!(
            NOISE_MA_CURRENT_WEIGHT_INVERSE[0],
            MA_CURRENT_WEIGHT_INVERSE[0]
        );
        for (predictor, weights) in NOISE_MA_PREDICTOR.iter().zip(NOISE_MA_CURRENT_WEIGHT) {
            for coefficient in 0..10 {
                let taps: i32 = predictor
                    .iter()
                    .map(|row| i32::from(row[coefficient]))
                    .sum();
                // the weights were worked out before the taps were rounded,
                // and each mixed tap is truncated: a few units apart
                let weight = i32::from(weights[coefficient]);
                assert!((32_768 - taps - weight).abs() <= 6, "{taps} and {weight}");
            }
        }
        for (weights, inverses) in NOISE_MA_CURRENT_WEIGHT
            .iter()
            .zip(NOISE_MA_CURRENT_WEIGHT_INVERSE)
        {
            for (weight, inverse) in weights.iter().zip(inverses) {
                let exact = 4096.0 * 32768.0 / f64::from(*weight);
                assert!(
                    (exact - f64::from(inverse)).abs() <= 2.5,
                    "{exact} {inverse}"
                );
            }
        }
        // about four times the mean square of each predictor's weights
        for (scale, weights) in SID_FIRST_STAGE_SCALE.iter().zip(NOISE_MA_CURRENT_WEIGHT) {
            let mean_square = weights
                .iter()
                .map(|w| (f64::from(*w) / 32_768.0).powi(2))
                .sum::<f64>()
                / 10.0;
            let ratio = f64::from(*scale) / 32_768.0 / (4.0 * mean_square);
            assert!((0.95..1.05).contains(&ratio), "{scale}: {ratio}");
        }
    }

    /// B.4.2.1's levels as gains: `√(10^(dB/10))` in Q3, to within the
    /// rounding of the smallest.
    #[test]
    fn the_sid_gains_are_b_4_2_1s_levels() {
        for (index, gain) in SID_GAINS.iter().enumerate() {
            let index = i32::try_from(index).unwrap();
            let decibels = match index {
                0 => -12,
                1..=6 => -4 + 4 * (index - 1),
                _ => 16 + 2 * (index - 6),
            };
            let exact = 8.0 * 10_f64.powf(f64::from(decibels) / 20.0);
            assert!(
                (f64::from(*gain) - exact).abs() <= exact * 0.01 + 1.0,
                "{decibels} dB: {gain} against {exact}"
            );
        }
    }

    /// The SID codebooks' subsets name rows that exist, and the low-band
    /// filter's autocorrelation peaks at lag zero.
    #[test]
    fn the_sid_subsets_and_the_low_band_filter_are_in_range() {
        assert!(
            SID_FIRST_STAGE_ROWS
                .iter()
                .all(|row| usize::from(*row) < FIRST_STAGE.len())
        );
        for rows in SID_SECOND_STAGE_ROWS {
            assert!(rows.iter().all(|row| usize::from(*row) < 32));
        }
        let [peak, rest @ ..] = LOW_BAND_CORRELATION;
        assert!(rest.iter().all(|value| value.abs() < peak));
    }

    /// `32/(32 − n)`: the mantissa and shift make it to within a unit in the
    /// mantissa, and the last entry, for no frames, is zero.
    #[test]
    fn the_start_factors_are_thirty_two_over_the_frames_that_count() {
        for n in 0..32_u8 {
            let exact = 32.0 / f64::from(32 - n);
            let mantissa = f64::from(LOUD_FRAMES_MANTISSA[usize::from(n)]);
            let value = mantissa / 32_768.0 * f64::from(1_u32 << LOUD_FRAMES_SHIFT[usize::from(n)]);
            assert!(
                (value - exact).abs() <= 2.0 / 32_768.0 * f64::from(1_u32 << 5),
                "{n}: {value} against {exact}"
            );
        }
        assert_eq!(LOUD_FRAMES_MANTISSA[32], 0);
    }

    /// Equation B.15's factor `αw / (kE · Ncur · 80)` for one and two
    /// energies, and one over the eighty samples of a frame for the lost
    /// first SID frame.
    #[test]
    fn the_sid_energy_factors_are_equation_b_15() {
        let q15 = |value: f64| nearest(value * 32_768.0);
        assert_eq!(i32::from(SID_ENERGY_FACTOR[0]), q15(1.0 / 80.0));
        assert_eq!(i32::from(SID_ENERGY_FACTOR[1]), q15(0.125 / (2.0 * 80.0)));
        assert_eq!(
            i32::from(SID_ENERGY_FACTOR[2]),
            q15(0.125 / (2.0 * 2.0 * 80.0))
        );
        assert_eq!(SID_ENERGY_HEADROOM, [0, 0, 1]);
    }

    #[test]
    fn the_initial_lsfs_are_i_pi_over_eleven() {
        for (index, value) in INITIAL_LSF.iter().enumerate() {
            let i = f64::from(u8::try_from(index + 1).unwrap());
            #[expect(clippy::cast_possible_truncation, reason = "the value is below 32768")]
            let truncated = (i * PI / 11.0 * 8192.0).floor() as i16;
            assert_eq!(*value, truncated, "i = {}", index + 1);
        }
    }

    /// Whatever the starting cosines are, they must describe a set of
    /// frequencies the codec could have decoded: ordered, so their cosines
    /// fall, and strictly inside `(0, π)`.
    #[test]
    fn the_initial_lsps_are_the_cosines_of_ordered_frequencies() {
        for pair in INITIAL_LSP.windows(2) {
            assert!(pair[0] > pair[1], "{INITIAL_LSP:?}");
        }
        assert!(INITIAL_LSP.iter().all(|q| *q > -32_768 && *q < 32_767));
    }

    #[test]
    fn the_gain_predictor_is_equation_69() {
        let printed = [0.68, 0.58, 0.34, 0.19];
        for (value, coefficient) in GAIN_PREDICTOR.iter().zip(printed) {
            assert_eq!(i32::from(*value), nearest(coefficient * 8192.0));
        }
    }

    #[test]
    fn the_output_filter_is_equation_91() {
        let zeros = [0.939_805_81, -1.879_583_4, 0.939_805_81];
        for (value, coefficient) in OUTPUT_HIGH_PASS_ZEROS.iter().zip(zeros) {
            assert_eq!(i32::from(*value), nearest(coefficient * 8192.0));
        }
        let poles = [1.0, 1.933_073_5, -0.935_891_99];
        for (value, coefficient) in OUTPUT_HIGH_PASS_POLES.iter().zip(poles) {
            assert_eq!(i32::from(*value), nearest(coefficient * 8192.0));
        }
    }

    #[test]
    fn the_cosine_table_is_the_cosine() {
        for (index, value) in COSINE.iter().enumerate() {
            let i = f64::from(u8::try_from(index).unwrap());
            let exact = nearest((i * PI / 64.0).cos() * 32768.0).min(32_767);
            assert_eq!(i32::from(*value), exact, "entry {index}");
        }
        for (index, slope) in COSINE_SLOPE.iter().enumerate() {
            let i = f64::from(u8::try_from(index).unwrap());
            let step = ((i + 1.0) * PI / 64.0).cos() - (i * PI / 64.0).cos();
            assert_eq!(
                i32::from(*slope),
                nearest(step * 32768.0 * 16.0),
                "entry {index}"
            );
        }
    }

    #[test]
    fn the_arithmetic_tables_are_their_functions() {
        for (index, value) in POWER_OF_TWO.iter().enumerate() {
            let i = f64::from(u8::try_from(index).unwrap());
            let exact = nearest(2_f64.powf(i / 32.0) * 16384.0).min(32_767);
            assert_eq!(i32::from(*value), exact, "2^({index}/32)");
        }
        // the logarithm table was rounded from a less precise evaluation and
        // sits a unit low in half its entries, so it is checked to within one
        for (index, value) in LOG2.iter().enumerate() {
            let i = f64::from(u8::try_from(index).unwrap());
            let exact = nearest((1.0 + i / 32.0).log2() * 32768.0).min(32_767);
            assert!(
                (i32::from(*value) - exact).abs() <= 1,
                "log2(1 + {index}/32): {value} against {exact}"
            );
        }
        for (index, value) in INVERSE_SQRT.iter().enumerate() {
            let i = f64::from(u8::try_from(index).unwrap());
            let exact = nearest(32768.0 / (1.0 + i / 16.0).sqrt()).min(32_767);
            assert_eq!(i32::from(*value), exact, "1/sqrt(1 + {index}/16)");
        }
    }

    #[test]
    fn the_input_filter_is_equation_1() {
        let zeros = [0.463_637_18, -0.927_247_05, 0.463_637_18];
        for (value, coefficient) in INPUT_HIGH_PASS_ZEROS.iter().zip(zeros) {
            assert_eq!(i32::from(*value), nearest(coefficient * 4096.0));
        }
        let poles = [1.0, 1.905_946_5, -0.911_402_4];
        for (value, coefficient) in INPUT_HIGH_PASS_POLES.iter().zip(poles) {
            assert_eq!(i32::from(*value), nearest(coefficient * 4096.0));
        }
    }

    /// Equation 3, entry for entry: the formula times 32767, rounded.
    #[test]
    fn the_analysis_window_is_equation_3() {
        for (index, value) in LP_WINDOW.iter().enumerate() {
            let n = f64::from(u8::try_from(index).unwrap());
            let window = if index < 200 {
                0.54 - 0.46 * (2.0 * PI * n / 399.0).cos()
            } else {
                (2.0 * PI * (n - 200.0) / 159.0).cos()
            };
            assert_eq!(i32::from(*value), nearest(window * 32767.0), "wlp({index})");
        }
    }

    /// Equations 6 and 7: `wlag(k)/1.0001` as a Q31 value, to within the
    /// precision it was evidently computed at, a few parts in `10^8`.
    #[test]
    fn the_lag_window_is_equation_6_over_the_noise_correction() {
        for (index, (high, low)) in LAG_WINDOW.iter().enumerate() {
            let k = f64::from(u8::try_from(index + 1).unwrap());
            let lag = (-0.5 * (2.0 * PI * 60.0 * k / 8000.0).powi(2)).exp() / 1.0001;
            let value = f64::from(*high) * 65536.0 + f64::from(*low) * 2.0;
            assert!(
                (value - lag * 2_147_483_648.0).abs() < 60.0,
                "wlag({k}): {value} against {}",
                lag * 2_147_483_648.0
            );
            assert!(*low >= 0);
        }
    }

    /// The grid of A.3.2.3: fifty intervals from `cos 0` to `cos π`.
    #[test]
    fn the_grid_is_fifty_steps_of_the_cosine() {
        for (index, value) in GRID.iter().enumerate() {
            let j = f64::from(u8::try_from(index).unwrap());
            #[expect(clippy::cast_possible_truncation, reason = "a cosine in Q15")]
            let truncated = ((j * PI / 50.0).cos() * 32768.0) as i32;
            let expected = truncated.clamp(-32_760, 32_760);
            assert_eq!(i32::from(*value), expected, "grid({index})");
        }
    }

    #[test]
    fn the_arccos_slopes_invert_the_cosine_table() {
        for (index, slope) in ARCCOS_SLOPE.iter().enumerate() {
            let start = if index == 0 {
                32_768
            } else {
                i32::from(COSINE[index])
            };
            let end = COSINE
                .get(index + 1)
                .map_or(-32_768, |value| i32::from(*value));
            let expected = nearest(1_048_576.0 / f64::from(end - start));
            assert_eq!(i32::from(*slope), expected, "segment {index}");
        }
    }

    #[test]
    fn the_codeword_maps_invert_the_row_maps() {
        for (row, codeword) in GA_CODEWORD.iter().enumerate() {
            assert_eq!(usize::from(GA_ROW[usize::from(*codeword)]), row);
        }
        for (row, codeword) in GB_CODEWORD.iter().enumerate() {
            assert_eq!(usize::from(GB_ROW[usize::from(*codeword)]), row);
        }
    }

    /// The preselection's thresholds each rise along their line, so that
    /// the search for the first one not passed can stop there.
    #[test]
    fn the_preselection_thresholds_rise() {
        for pair in GA_THRESHOLDS.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        for pair in GB_THRESHOLDS.windows(2) {
            assert!(pair[0] < pair[1]);
        }
        assert!(PRESELECTION_SLOPES.iter().all(|slope| *slope > 0));
        assert!(PRESELECTION_OFFSETS.iter().all(|offset| *offset > 0));
    }

    /// §3.7.1 describes `b30` as a Hamming-windowed sinc, truncated at ±29
    /// and zero at ±30, with its cut-off at 3600 Hz in the oversampled
    /// domain. The window below spans ±29.5 samples; with it, and the gain
    /// that makes the centre tap agree, every coefficient lands within two
    /// units of the table, and the zeros of the sinc fall where the table has
    /// its zeros.
    #[test]
    fn b30_is_the_windowed_sinc_the_text_describes() {
        let centre = f64::from(INTERPOLATION_B30[0]);
        for (index, value) in INTERPOLATION_B30.iter().enumerate() {
            let n = f64::from(u8::try_from(index).unwrap());
            let x = 2.0 * 3600.0 / 24_000.0 * n;
            let sinc = if index == 0 {
                1.0
            } else {
                (PI * x).sin() / (PI * x)
            };
            let window = 0.54 + 0.46 * (PI * n / 29.5).cos();
            let expected = nearest(centre * sinc * window);
            assert!(
                (i32::from(*value) - expected).abs() <= 2,
                "b30({index}) is {value}, the formula gives {expected}"
            );
            if index % 10 == 0 && index > 0 {
                assert_eq!(*value, 0, "b30({index}) sits on a zero of the sinc");
            }
        }
    }
}
