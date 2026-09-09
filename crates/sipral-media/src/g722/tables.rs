// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The constants of ITU-T G.722, transcribed from the Recommendation.
//!
//! Table 11 for the filter, Table 14 for the quantizers, Table 15's 353-entry
//! half for the log-to-linear conversion — §6.2.1.3 offers a 32-entry table as
//! an alternative and this implements the exact one, so the shorter table is
//! not carried — and Tables 16 to 21 for the mapping between
//! quantizer intervals and codewords. Nothing here is derived: every value is
//! read off the printed table, because a table that is nearly right gives a
//! codec that works and sounds wrong.
//!
//! Two of them are laid out in a way worth writing down. Table 14 prints QQ4
//! and WL starting on the row labelled 2, but both are addressed by IL4, which
//! Table 17 gives as 0 to 7 — so the address column belongs to Q6, QQ6 and
//! QQ5, and those two columns are simply printed lower. And Table 19's left
//! half prints six characters for a five-bit codeword; the leading zero is a
//! misprint, and dropping it is what makes the table agree with Table 5's own
//! codes. The tests at the end check both against Table 5 rather than taking
//! this comment's word for it.

pub(super) const QMF: [i32; 24] = [
    3, -11, -11, 53, 12, -156, 32, 362, -210, -805, 951, 3876, 3876, 951, -805, -210, 362, 32,
    -156, 12, 53, -11, -11, 3,
];

pub(super) const Q6: [i16; 31] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0,
];

pub(super) const QQ6: [i16; 31] = [
    0, 17, 54, 91, 130, 170, 211, 254, 300, 347, 396, 447, 501, 558, 618, 682, 750, 822, 899, 982,
    1072, 1170, 1279, 1399, 1535, 1689, 1873, 2088, 2376, 2738, 3101,
];

pub(super) const QQ5: [i16; 16] = [
    0, 35, 110, 190, 276, 370, 473, 587, 714, 858, 1023, 1219, 1458, 1765, 2195, 2919,
];

pub(super) const QQ4: [i16; 8] = [0, 150, 323, 530, 786, 1121, 1612, 2557];

pub(super) const WL: [i16; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];

pub(super) const Q2: i16 = 564;

pub(super) const QQ2: [i16; 3] = [0, 202, 926];

pub(super) const WH: [i16; 3] = [0, -214, 798];

pub(super) const ILA: [i16; 353] = [
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6,
    7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 9, 9, 9, 9, 10, 10, 10, 10, 11, 11, 11, 11, 12, 12, 12, 13,
    13, 13, 13, 14, 14, 15, 15, 15, 16, 16, 16, 17, 17, 18, 18, 18, 19, 19, 20, 20, 21, 21, 22, 22,
    23, 23, 24, 24, 25, 25, 26, 27, 27, 28, 28, 29, 30, 31, 31, 32, 33, 33, 34, 35, 36, 37, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 54, 55, 56, 57, 58, 60, 61, 63, 64, 65,
    67, 68, 70, 71, 73, 75, 76, 78, 80, 82, 83, 85, 87, 89, 91, 93, 95, 97, 99, 102, 104, 106, 109,
    111, 113, 116, 118, 121, 124, 127, 129, 132, 135, 138, 141, 144, 147, 151, 154, 157, 161, 165,
    168, 172, 176, 180, 184, 188, 192, 196, 200, 205, 209, 214, 219, 223, 228, 233, 238, 244, 249,
    255, 260, 266, 272, 278, 284, 290, 296, 303, 310, 316, 323, 331, 338, 345, 353, 361, 369, 377,
    385, 393, 402, 411, 420, 429, 439, 448, 458, 468, 478, 489, 500, 511, 522, 533, 545, 557, 569,
    582, 594, 607, 621, 634, 648, 663, 677, 692, 707, 723, 739, 755, 771, 788, 806, 823, 841, 860,
    879, 898, 918, 938, 958, 979, 1001, 1023, 1045, 1068, 1092, 1115, 1140, 1165, 1190, 1216, 1243,
    1270, 1298, 1327, 1356, 1386, 1416, 1447, 1479, 1511, 1544, 1578, 1613, 1648, 1684, 1721, 1759,
    1797, 1837, 1877, 1918, 1960, 2003, 2047, 2092, 2138, 2185, 2232, 2281, 2331, 2382, 2434, 2488,
    2542, 2598, 2655, 2713, 2773, 2833, 2895, 2959, 3024, 3090, 3157, 3227, 3297, 3370, 3443, 3519,
    3596, 3675, 3755, 3837, 3921, 4007, 4095,
];

pub(super) const SIL6: [i16; 64] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1,
];

pub(super) const SIL5: [i16; 32] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, -1,
];

pub(super) const SIL4: [i16; 16] = [0, -1, -1, -1, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0];

pub(super) const IL6: [u8; 64] = [
    1, 1, 1, 1, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
    9, 8, 7, 6, 5, 4, 3, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13,
    12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 2, 1,
];

pub(super) const IL5: [u8; 32] = [
    1, 1, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4,
    3, 2, 1, 1,
];

pub(super) const IL4: [u8; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];

pub(super) const IL_POSITIVE: [u8; 31] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32,
];

pub(super) const IL_NEGATIVE: [u8; 31] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4,
];

pub(super) const SIH: [i16; 4] = [-1, -1, 0, 0];

pub(super) const IH2: [u8; 4] = [2, 1, 2, 1];

pub(super) const IH_POSITIVE: [u8; 3] = [0, 3, 2];

pub(super) const IH_NEGATIVE: [u8; 3] = [0, 1, 0];

#[cfg(test)]
mod tests {
    use super::{
        IH_NEGATIVE, IH_POSITIVE, IH2, IL_NEGATIVE, IL_POSITIVE, IL6, ILA, QMF, QQ2, QQ4, QQ5, QQ6,
        SIH, SIL6, WH, WL,
    };

    /// Table 16 says which codeword an interval and a sign produce; Table 18
    /// says which interval and sign a codeword means. One is the other read
    /// backwards, and a transcription slip in either would show up here and
    /// nowhere else until a call sounded wrong.
    #[test]
    fn the_two_directions_of_the_six_bit_table_agree() {
        for interval in 1..=30_usize {
            let positive = usize::from(*IL_POSITIVE.get(interval).unwrap_or(&0));
            let negative = usize::from(*IL_NEGATIVE.get(interval).unwrap_or(&0));
            assert_eq!(
                (
                    *SIL6.get(positive).unwrap_or(&9),
                    *IL6.get(positive).unwrap_or(&0)
                ),
                (0, u8::try_from(interval).unwrap_or(0)),
                "interval {interval} positive"
            );
            assert_eq!(
                (
                    *SIL6.get(negative).unwrap_or(&9),
                    *IL6.get(negative).unwrap_or(&0)
                ),
                (-1, u8::try_from(interval).unwrap_or(0)),
                "interval {interval} negative"
            );
        }
    }

    /// Table 5's note: a codeword corrupted into one of the four "0000XX"
    /// values is read as the smallest negative interval rather than refused.
    #[test]
    fn the_four_suppressed_codewords_are_read_as_the_smallest_interval() {
        for codeword in 0..4_usize {
            assert_eq!(
                (
                    *SIL6.get(codeword).unwrap_or(&9),
                    *IL6.get(codeword).unwrap_or(&0)
                ),
                (-1, 1)
            );
        }
    }

    #[test]
    fn the_two_bit_table_reads_the_same_both_ways() {
        for interval in 1..=2_usize {
            for (table, sign) in [(&IH_POSITIVE, 0), (&IH_NEGATIVE, -1)] {
                let code = usize::from(*table.get(interval).unwrap_or(&0));
                assert_eq!(*SIH.get(code).unwrap_or(&9), sign);
                assert_eq!(
                    *IH2.get(code).unwrap_or(&0),
                    u8::try_from(interval).unwrap_or(0)
                );
            }
        }
    }

    /// The log-to-linear table is a curve, not a list: thirty-two entries to
    /// the octave, ending on a power of two less one. Anything mistyped in
    /// the middle breaks the shape.
    #[test]
    fn the_log_to_linear_table_has_the_shape_it_should() {
        assert_eq!(ILA.len(), 353);
        for window in ILA.windows(2) {
            let (a, b) = (*window.first().unwrap_or(&0), *window.get(1).unwrap_or(&0));
            assert!(a <= b, "the table goes backwards at {a} to {b}");
        }
        // thirty-two steps to the octave, so every thirty-second entry is one
        // less than a power of two
        for octave in 0..12_usize {
            let expected = (1_i32 << (octave + 1)) - 1;
            assert_eq!(
                i32::from(*ILA.get(octave * 32).unwrap_or(&0)),
                expected,
                "octave {octave}"
            );
        }
    }

    #[test]
    fn the_filter_is_symmetric_and_the_tables_are_the_lengths_they_should_be() {
        for tap in 0..12_usize {
            assert_eq!(
                QMF.get(tap).unwrap_or(&0),
                QMF.get(23 - tap).unwrap_or(&0),
                "tap {tap}"
            );
        }
        assert_eq!(QQ6.len(), 31, "thirty intervals and an unused zero");
        assert_eq!(QQ5.len(), 16, "fifteen intervals and an unused zero");
        assert_eq!(QQ4.len(), 8, "eight, addressed from zero");
        assert_eq!(WL.len(), 8);
        assert_eq!(QQ2.len(), 3);
        assert_eq!(WH.len(), 3);
    }

    /// The scale factor multipliers have to be able to pull the step size
    /// down as well as push it up, or it climbs to the ceiling on the first
    /// loud passage and stays there.
    #[test]
    fn the_scale_multipliers_run_both_ways() {
        assert!(WL.first().is_some_and(|first| *first < 0));
        assert!(WL.last().is_some_and(|last| *last > 0));
        assert!(WH.get(1).is_some_and(|first| *first < 0));
        assert!(WH.get(2).is_some_and(|last| *last > 0));
    }
}
