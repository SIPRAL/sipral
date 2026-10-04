// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The anti-replay window of RFC 6347 §4.1.2.6.

use crate::Error;

/// The sequence numbers of one epoch that have already authenticated, kept
/// for the 64 highest.
///
/// §4.1.2.6 splits the work in two, and so does this type: [`check`] is the
/// first thing done to a record and changes nothing, so a forged record can
/// be refused cheaply without moving the window; [`accept`] is called only
/// once the record has authenticated, because "the receive window is updated
/// only if the MAC verification succeeds". Calling `accept` for a record that
/// did not authenticate would let a forgery push the window forward and shut
/// out the genuine records behind it.
///
/// The window is 64 wide, the size §4.1.2.6 says "SHOULD be employed as the
/// default". It belongs to one epoch: sequence numbers start again at zero in
/// the next one, and so does the window.
///
/// [`check`]: ReplayWindow::check
/// [`accept`]: ReplayWindow::accept
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplayWindow {
    /// The highest sequence number that has authenticated, once one has.
    right: Option<u64>,
    /// Bit `i` set means `right - i` has authenticated; bit 0 is `right`.
    seen: u64,
}

impl ReplayWindow {
    /// How many sequence numbers, counting the highest, the window remembers.
    pub const WIDTH: u64 = 64;

    /// A window that has seen nothing.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            right: None,
            seen: 0,
        }
    }

    /// Whether a record carrying `sequence` may go on to authentication.
    ///
    /// # Errors
    ///
    /// [`Error::Replayed`] when `sequence` has already authenticated, or lies
    /// to the left of the window, where whether it has cannot be known.
    pub const fn check(&self, sequence: u64) -> Result<(), Error> {
        let Some(right) = self.right else {
            return Ok(());
        };
        if sequence > right {
            return Ok(());
        }
        let behind = right - sequence;
        if behind >= Self::WIDTH || self.seen & (1 << behind) != 0 {
            return Err(Error::Replayed);
        }
        Ok(())
    }

    /// Record that a record carrying `sequence` authenticated.
    pub const fn accept(&mut self, sequence: u64) {
        match self.right {
            None => {
                self.right = Some(sequence);
                self.seen = 1;
            }
            Some(right) if sequence > right => {
                let ahead = sequence - right;
                self.seen = if ahead >= Self::WIDTH {
                    1
                } else {
                    (self.seen << ahead) | 1
                };
                self.right = Some(sequence);
            }
            Some(right) => {
                let behind = right - sequence;
                if behind < Self::WIDTH {
                    self.seen |= 1 << behind;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_checked_record_is_not_remembered_until_it_is_accepted() {
        let mut window = ReplayWindow::new();
        assert_eq!(window.check(0), Ok(()));
        // a forgery that failed authentication is checked and never accepted
        assert_eq!(window.check(0), Ok(()));
        window.accept(0);
        assert_eq!(window.check(0), Err(Error::Replayed));
        assert_eq!(window.check(1), Ok(()));
    }

    #[test]
    fn records_out_of_order_inside_the_window_are_each_taken_once() {
        let mut window = ReplayWindow::new();
        for sequence in [10, 7, 12, 8, 11] {
            assert_eq!(window.check(sequence), Ok(()), "{sequence}");
            window.accept(sequence);
        }
        for sequence in [7, 8, 10, 11, 12] {
            assert_eq!(window.check(sequence), Err(Error::Replayed), "{sequence}");
        }
        for sequence in [9, 13, 1000] {
            assert_eq!(window.check(sequence), Ok(()), "{sequence}");
        }
    }

    #[test]
    fn the_left_edge_is_sixty_four_back_from_the_highest() {
        let mut window = ReplayWindow::new();
        window.accept(100);
        // 100 - 63 is the oldest the window still speaks for
        assert_eq!(window.check(37), Ok(()));
        assert_eq!(window.check(36), Err(Error::Replayed));
        window.accept(37);
        assert_eq!(window.check(37), Err(Error::Replayed));
        // one step right and 37 falls off the edge, refused either way
        window.accept(101);
        assert_eq!(window.check(37), Err(Error::Replayed));
        assert_eq!(window.check(38), Ok(()));
    }

    #[test]
    fn a_jump_keeps_what_is_still_inside_and_forgets_what_is_not() {
        let mut window = ReplayWindow::new();
        window.accept(5);
        window.accept(5 + 63);
        assert_eq!(window.check(5), Err(Error::Replayed));

        let mut window = ReplayWindow::new();
        window.accept(5);
        window.accept(4);
        window.accept(5 + 64);
        // 5 is now exactly 64 behind: outside, refused for being too old
        assert_eq!(window.check(5), Err(Error::Replayed));
        // and nothing between it and the new right edge was carried over
        for sequence in 6..(5 + 64) {
            assert_eq!(window.check(sequence), Ok(()), "{sequence}");
        }
    }
}
