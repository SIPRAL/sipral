// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Byte ranges into a message buffer, and the reusable index a parse fills.

/// A byte range into some buffer. Never dereferenced on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    /// First byte.
    pub start: u32,
    /// One past the last byte.
    pub end: u32,
}

impl Span {
    /// An empty span at `at`.
    #[must_use]
    pub const fn empty(at: u32) -> Self {
        Self { start: at, end: at }
    }

    /// The bytes covered, or an empty slice if the span does not fit `buf`.
    #[must_use]
    pub fn slice(self, buf: &[u8]) -> &[u8] {
        buf.get(self.start as usize..self.end as usize)
            .unwrap_or_default()
    }

    /// Length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.end.saturating_sub(self.start) as usize
    }

    /// Whether the span covers nothing.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.end <= self.start
    }
}

/// One header field, located but not interpreted.
///
/// A value folded across lines (RFC 3261 §7.3.1) is a single slot whose value
/// span covers the continuation lines, CRLF and all. A header repeated on
/// several lines is one slot per line, kept in wire order.
#[derive(Clone, Copy, Debug)]
pub struct HeaderSlot {
    /// The field name, without the colon and without surrounding whitespace.
    pub name: Span,
    /// The field value, trimmed of leading and trailing whitespace.
    pub value: Span,
}

/// Reusable index for one parse. Cleared between messages, not freed, so a
/// steady-state loop stops allocating once it has grown to its working size.
#[derive(Debug, Default)]
pub struct ParseScratch {
    pub(crate) slots: Vec<HeaderSlot>,
}

impl ParseScratch {
    /// An empty index.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop the located headers, keep the allocation.
    pub fn clear(&mut self) {
        self.slots.clear();
    }

    /// How many slots fit without reallocating.
    #[must_use]
    pub fn slot_capacity(&self) -> usize {
        self.slots.capacity()
    }
}

#[cfg(test)]
mod tests {
    use super::{ParseScratch, Span};

    #[test]
    fn span_slices_and_measures() {
        let buf = b"INVITE sip:a@b SIP/2.0";
        let s = Span { start: 0, end: 6 };
        assert_eq!(s.slice(buf), b"INVITE");
        assert_eq!(s.len(), 6);
        assert!(!s.is_empty());
    }

    #[test]
    fn span_out_of_range_is_empty_not_a_panic() {
        let buf = b"short";
        let s = Span { start: 2, end: 900 };
        assert_eq!(s.slice(buf), b"");
    }

    #[test]
    fn inverted_span_does_not_underflow() {
        let s = Span { start: 9, end: 3 };
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
    }

    #[test]
    fn scratch_keeps_its_allocation_across_clears() {
        let mut scratch = ParseScratch::new();
        scratch.slots.reserve(32);
        let cap = scratch.slot_capacity();
        scratch.clear();
        assert_eq!(scratch.slot_capacity(), cap);
    }
}
