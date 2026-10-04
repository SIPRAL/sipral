// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Hostile packets, through SRTP and SRTCP unprotect.
//!
//! Every byte `unprotect_rtp` and `unprotect_rtcp` read comes off the wire
//! before any of it is trusted: the header, the sequence number the replay
//! window and rollover estimate are built from, the trailing authentication
//! tag, and the master key identifier when the policy carries one. With a
//! fixed key the authentication check fails on almost anything fuzzing finds,
//! which is fine -- what is under test is everything ahead of that check:
//! length arithmetic, the header parse, the rollover estimate and the replay
//! window, none of which may panic on a forged or truncated packet, and the
//! two calls must never touch a byte outside what was handed in.
//!
//! Two of those four are state that only exists between packets. So the input
//! is cut into datagrams -- an octet of length, then that many bytes, the
//! shape the `rtp_dtmf` target uses -- and the whole run goes through one
//! `Unprotector` per suite rather than one per packet. A fresh unprotector
//! sees every packet as the first it has ever seen: its window is empty, its
//! rollover counter is zero, and neither of the two is reached at all. One
//! across the run reaches both, and a reordered or repeated datagram inside
//! the same seed is what drives them.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_rtp::srtp::{Master, Policy, Suite, Unprotector};

/// A key or salt of `len` octets, filled with a fixed, recognisable pattern
/// -- the exact bytes do not matter, only that authentication fails on
/// almost anything fuzzing finds, which is the point (see the module docs).
fn filled(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

fuzz_target!(|data: &[u8]| {
    for suite in [
        Suite::AesCm80,
        Suite::AesCm32,
        Suite::AesF8,
        Suite::Aes256Cm80,
        Suite::Aes256Cm32,
        Suite::AeadAes128Gcm,
        Suite::AeadAes256Gcm,
    ] {
        let key = filled(0x42, suite.key_len());
        let salt = filled(0x24, suite.salt_len());
        // one of each for the whole run: RTP and RTCP keep indices and
        // windows of their own, exactly as an endpoint does
        let mut rtp = Unprotector::new(Policy::new(suite), Master::new(&key, &salt));
        let mut rtcp = Unprotector::new(Policy::new(suite), Master::new(&key, &salt));

        let mut rest = data;
        while let Some((&len, tail)) = rest.split_first() {
            let take = usize::from(len).min(tail.len());
            let (datagram, tail) = tail.split_at(take);
            rest = tail;

            let mut packet = datagram.to_vec();
            if let Ok(len) = rtp.unprotect_rtp(&mut packet) {
                assert!(len <= datagram.len(), "unprotect_rtp grew the packet");
            }

            let mut packet = datagram.to_vec();
            if let Ok(len) = rtcp.unprotect_rtcp(&mut packet) {
                assert!(len <= datagram.len(), "unprotect_rtcp grew the packet");
            }
        }
    }
});
