// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Octets nobody's encoder produced, through the G.729 decoder twice over:
//! once as one RTP payload, read by [`sipral_media::g729::Payload`] and
//! decoded by [`sipral_media::g729::Decoder::decode_into`], and once as a
//! stream of ten-octet frames, two-octet SID frames and lost frames, each
//! announced by one octet, through [`sipral_media::g729::Decoder::decode`]
//! and [`sipral_media::g729::Decoder::conceal`]. Every frame decoded or
//! concealed is then encoded again by [`sipral_media::g729::Encoder`] and
//! decoded by a second decoder, so the encoder meets whatever the decoder
//! can be made to produce.
//!
//! Every pattern of eighty bits is a G.729 frame, so the decoder has nothing
//! to refuse: what is checked is that no frame, and no run of losses, panics
//! the fixed point, that a payload is read as whole frames and at most one
//! SID frame and nothing else, and that a SID frame's energy is one of Annex
//! B's levels.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::g729::{Decoder, Encoder, FRAME_OCTETS, FRAME_SAMPLES, Payload, SID_OCTETS, Sid};

fuzz_target!(|data: &[u8]| {
    // the whole input as one payload
    let left = data.len() % FRAME_OCTETS;
    let parsed = Payload::parse(data);
    assert_eq!(parsed.is_some(), left == 0 || left == SID_OCTETS);
    if let Some(payload) = parsed {
        assert_eq!(payload.frame_count(), data.len() / FRAME_OCTETS);
        assert_eq!(payload.sid().is_some(), left == SID_OCTETS);
        let mut samples = vec![0_i16; payload.frame_count() * FRAME_SAMPLES];
        let written = Decoder::new().decode_into(payload.speech(), &mut samples);
        assert_eq!(written, samples.len());
        if let Some(sid) = payload.sid() {
            assert!((-12..=66).contains(&sid.energy_db()));
        }
    }

    // the same octets as a stream: a tag octet, then what it names
    let mut decoder = Decoder::new();
    let mut encoder = Encoder::new();
    let mut second = Decoder::new();
    let mut rest = data;
    while let Some((&tag, after)) = rest.split_first() {
        rest = after;
        let heard = match tag % 3 {
            0 => {
                let Some((frame, after)) = rest.split_first_chunk::<FRAME_OCTETS>() else {
                    break;
                };
                rest = after;
                decoder.decode(frame)
            }
            1 => {
                let Some((octets, after)) = rest.split_first_chunk::<SID_OCTETS>() else {
                    break;
                };
                rest = after;
                let sid = Sid::from_octets(*octets);
                assert!(sid.energy_index() < 32);
                assert_eq!(sid.energy_db() % 2, 0);
                continue;
            }
            _ => decoder.conceal(),
        };
        let frame = encoder.encode(&heard);
        let _ = second.decode(&frame);
    }
});
