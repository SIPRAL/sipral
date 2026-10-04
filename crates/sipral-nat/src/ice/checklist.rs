// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The arithmetic of a checklist: pair priorities, pruning, the pair limit and
//! the states the frozen algorithm starts from (RFC 8445 §6.1.2).
//!
//! Everything here is a pure function over numbers and keys, so the parts of
//! the specification that come with a worked example can be held to it
//! without an agent, a clock or a network in the way. The agent in
//! [`super::full`] owns the pairs and calls these.

use super::candidate::{ComponentId, Foundation};

/// The largest priority a candidate may have: "a positive integer between 1
/// and (2**31 - 1)" (RFC 8445 §5.1.2).
pub(crate) const MAX_PRIORITY: u32 = 0x7fff_ffff;

/// Where a candidate pair stands (RFC 8445 §6.1.2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairState {
    /// No check has been sent, and none may be until the pair is unfrozen.
    Frozen,
    /// No check has been sent, and one may be.
    Waiting,
    /// A check is out and its transaction has not ended.
    InProgress,
    /// A check produced a successful, symmetric response.
    Succeeded,
    /// A check timed out, was refused, or came back from somewhere else.
    Failed,
}

/// A pair's priority from the priorities of its two candidates (RFC 8445
/// §6.1.2.3): `2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)`, where G is the
/// candidate the controlling agent provided and D the controlled agent's.
///
/// A peer is not trusted to keep its priorities inside §5.1.2's range, so both
/// are clamped to it first; inside that range the formula cannot overflow
/// sixty-four bits.
#[must_use]
pub fn pair_priority(controlling: u32, controlled: u32) -> u64 {
    let g = u64::from(controlling.min(MAX_PRIORITY));
    let d = u64::from(controlled.min(MAX_PRIORITY));
    (g.min(d) << 32) + 2 * g.max(d) + u64::from(g > d)
}

/// What the frozen algorithm's starting step needs to know about one pair.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Slot<'a> {
    /// The pair's checklist, by its position in the checklist set.
    pub(crate) checklist: usize,
    /// The pair's component.
    pub(crate) component: ComponentId,
    /// The pair's priority.
    pub(crate) priority: u64,
    /// The pair's foundation: its local candidate's and its remote
    /// candidate's, taken together.
    pub(crate) foundation: (&'a Foundation, &'a Foundation),
}

/// The pairs to put in the Waiting state when a checklist set is formed, as
/// positions in `slots`; everything else starts Frozen.
///
/// "For each foundation, the agent sets the state of exactly one candidate
/// pair to the Waiting state (unfreezing it). The candidate pair to unfreeze
/// is chosen by finding the first candidate pair (ordered by the lowest
/// component ID and then the highest priority if component IDs are equal) in
/// the first checklist (according to the usage-defined checklist set order)
/// that has that foundation" (RFC 8445 §6.1.2.6, step 4).
pub(crate) fn initially_waiting(slots: &[Slot<'_>]) -> Vec<usize> {
    let mut order: Vec<usize> = (0..slots.len()).collect();
    order.sort_by(|left, right| {
        let (Some(a), Some(b)) = (slots.get(*left), slots.get(*right)) else {
            return core::cmp::Ordering::Equal;
        };
        a.checklist
            .cmp(&b.checklist)
            .then(a.component.cmp(&b.component))
            .then(b.priority.cmp(&a.priority))
    });
    let mut seen: Vec<(&Foundation, &Foundation)> = Vec::new();
    let mut waiting = Vec::new();
    for position in order {
        let Some(slot) = slots.get(position) else {
            continue;
        };
        if !seen.contains(&slot.foundation) {
            seen.push(slot.foundation);
            waiting.push(position);
        }
    }
    waiting
}

/// Remove every item whose key an earlier item already had (RFC 8445
/// §6.1.2.4: "removing a candidate pair if it is redundant with a
/// higher-priority candidate pair in the same checklist").
///
/// The input has to be sorted by descending priority already, which is what
/// makes "earlier" mean "higher priority".
pub(crate) fn prune_sorted<T, K: PartialEq>(items: &mut Vec<T>, key: impl Fn(&T) -> K) {
    let mut kept: Vec<K> = Vec::with_capacity(items.len());
    items.retain(|item| {
        let this = key(item);
        if kept.contains(&this) {
            false
        } else {
            kept.push(this);
            true
        }
    });
}

/// How many pairs each checklist may keep so that the set holds no more than
/// `limit` (RFC 8445 §6.1.2.5).
///
/// "The discarding SHOULD be done evenly so that the number of candidate pairs
/// in each checklist is reduced the same amount": one pair at a time comes off
/// whichever checklist is currently the longest, which evens the lengths out
/// from the top rather than cutting every list by the same count and leaving a
/// short list with nothing.
pub(crate) fn trim_evenly(sizes: &[usize], limit: usize) -> Vec<usize> {
    let mut kept = sizes.to_vec();
    let mut total: usize = kept.iter().sum();
    while total > limit {
        let Some(longest) = kept.iter_mut().max_by_key(|size| **size) else {
            break;
        };
        if *longest == 0 {
            break;
        }
        *longest -= 1;
        total -= 1;
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::{MAX_PRIORITY, Slot, initially_waiting, pair_priority, prune_sorted, trim_evenly};
    use crate::ice::candidate::{ComponentId, Foundation};

    #[test]
    fn the_pair_priority_is_the_formula_in_section_6_1_2_3() {
        // G > D: the minimum goes in the high word, twice the maximum below
        // it, and the tie bit says the controlling side's candidate was the
        // larger
        assert_eq!(pair_priority(200, 100), (100 << 32) + 400 + 1);
        assert_eq!(pair_priority(100, 200), (100 << 32) + 400);
        assert_eq!(pair_priority(7, 7), (7 << 32) + 14);
    }

    #[test]
    fn swapping_the_roles_changes_only_the_tie_bit() {
        let as_controlling = pair_priority(2_130_706_431, 1_694_498_815);
        let as_controlled = pair_priority(1_694_498_815, 2_130_706_431);
        assert_eq!(as_controlling - as_controlled, 1);
    }

    #[test]
    fn a_priority_outside_the_range_is_clamped_rather_than_overflowing() {
        assert_eq!(
            pair_priority(u32::MAX, u32::MAX),
            pair_priority(MAX_PRIORITY, MAX_PRIORITY)
        );
        assert_eq!(pair_priority(u32::MAX, 5), pair_priority(MAX_PRIORITY, 5));
    }

    fn foundations(names: &[&str]) -> Vec<Foundation> {
        names
            .iter()
            .map(|name| Foundation::parse(name).expect("a valid foundation"))
            .collect()
    }

    #[test]
    fn the_starting_states_are_the_ones_in_table_1() {
        // RFC 8445 SS6.1.2.6, Table 1: three checklists, five foundations.
        // Each pair here has its own local foundation and one shared remote
        // foundation, so the local one alone names the column.
        let locals = foundations(&["1", "2", "3", "4", "5"]);
        let remote = Foundation::parse("9").expect("a valid foundation");
        let rtp = ComponentId::RTP;
        let slot = |checklist: usize, column: usize, priority: u64| Slot {
            checklist,
            component: rtp,
            priority,
            foundation: (&locals[column], &remote),
        };
        let slots = [
            slot(0, 0, 90),
            slot(0, 1, 80),
            slot(0, 2, 70),
            slot(1, 0, 90),
            slot(1, 1, 80),
            slot(1, 2, 70),
            slot(1, 3, 60),
            slot(2, 0, 90),
            slot(2, 4, 50),
        ];
        let mut waiting = initially_waiting(&slots);
        waiting.sort_unstable();
        // m1 f1, m1 f2, m1 f3, m2 f4, m3 f5
        assert_eq!(waiting, vec![0, 1, 2, 6, 8]);
    }

    #[test]
    fn within_a_foundation_the_lowest_component_wins_over_the_highest_priority() {
        let local = Foundation::parse("1").expect("a valid foundation");
        let remote = Foundation::parse("2").expect("a valid foundation");
        let slots = [
            Slot {
                checklist: 0,
                component: ComponentId::RTCP,
                priority: 1_000,
                foundation: (&local, &remote),
            },
            Slot {
                checklist: 0,
                component: ComponentId::RTP,
                priority: 10,
                foundation: (&local, &remote),
            },
        ];
        assert_eq!(initially_waiting(&slots), vec![1]);
    }

    #[test]
    fn pruning_keeps_the_first_of_each_key() {
        let mut pairs = vec![("host", "r1", 9), ("host", "r1", 5), ("host", "r2", 4)];
        prune_sorted(&mut pairs, |pair| (pair.0, pair.1));
        assert_eq!(pairs, vec![("host", "r1", 9), ("host", "r2", 4)]);
    }

    #[test]
    fn the_pair_limit_is_taken_off_the_longest_checklists_first() {
        assert_eq!(trim_evenly(&[80, 40], 100), vec![60, 40]);
        assert_eq!(trim_evenly(&[70, 70], 100), vec![50, 50]);
        assert_eq!(trim_evenly(&[10, 200], 100), vec![10, 90]);
        assert_eq!(trim_evenly(&[3, 4], 100), vec![3, 4]);
        assert_eq!(trim_evenly(&[5], 0), vec![0]);
    }
}
