// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Octets nobody's encoder produced, through the G.729 decoder twice over:
//! once as one RTP payload, read by [`sipral_media::g729::Payload`] and
//! decoded by [`sipral_media::g729::Decoder::decode_into`], and once as a
//! stream of ten-octet frames, two-octet SID frames, lost frames and frames
//! the far end did not send, each announced by one octet, through
//! [`sipral_media::g729::Decoder::decode`], `decode_sid`, `conceal` and
//! `untransmitted`. Every frame decoded, concealed or filled with comfort
//! noise is then encoded again by an [`sipral_media::g729::Encoder`] with
//! Annex B's DTX on, and what that sends — speech, a SID frame or nothing —
//! decoded by a second decoder, so the encoder, its voice activity detector
//! and its SID quantizer meet whatever the decoder can be made to produce.
//!
//! Every pattern of eighty bits is a G.729 frame and every pattern of
//! sixteen a SID frame, so the decoder has nothing to refuse: what is
//! checked is that no frame, and no run of losses or pauses, panics the
//! fixed point, that a payload is read as whole frames and at most one SID
//! frame and nothing else, that a SID frame's energy is one of Annex B's
//! levels, and that the encoder sends ten octets, two or none.

#![no_main]

use libfuzzer_sys::fuzz_target;
use sipral_media::g729::{
    Decoder, Encoded, Encoder, FRAME_OCTETS, FRAME_SAMPLES, Payload, SID_OCTETS, Sid,
};

fuzz_target!(|data: &[u8]| {
    // the whole input as one payload, with room for its SID frame
    let left = data.len() % FRAME_OCTETS;
    let parsed = Payload::parse(data);
    assert_eq!(parsed.is_some(), left == 0 || left == SID_OCTETS);
    if let Some(payload) = parsed {
        assert_eq!(payload.frame_count(), data.len() / FRAME_OCTETS);
        assert_eq!(payload.sid().is_some(), left == SID_OCTETS);
        let frames = payload.frame_count() + usize::from(payload.sid().is_some());
        let mut samples = vec![0_i16; frames * FRAME_SAMPLES];
        let written = Decoder::new().decode_into(data, &mut samples);
        assert_eq!(written, samples.len());
        if let Some(sid) = payload.sid() {
            assert!((-12..=66).contains(&sid.energy_db()));
        }
    }

    // the same octets as a stream: a tag octet, then what it names
    let mut decoder = Decoder::new();
    let mut encoder = Encoder::with_dtx();
    let mut second = Decoder::new();
    let mut rest = data;
    while let Some((&tag, after)) = rest.split_first() {
        rest = after;
        let heard = match tag % 4 {
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
                decoder.decode_sid(sid)
            }
            2 => decoder.conceal(),
            _ => decoder.untransmitted(),
        };
        let sent = encoder.encode(&heard);
        assert!(matches!(sent.octets().len(), 0 | SID_OCTETS | FRAME_OCTETS));
        let _ = match sent {
            Encoded::Speech(frame) => second.decode(&frame),
            Encoded::Sid(sid) => second.decode_sid(sid),
            Encoded::Nothing => second.untransmitted(),
        };
    }
});
