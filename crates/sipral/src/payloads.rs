// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Which codec each dynamic payload type number has meant on one call.
//!
//! RFC 3264 §8.3.2 lets a re-offer change the format list but says "the mapping from a particular
//! dynamic payload type number to a particular codec within that media stream MUST NOT change for
//! the duration of a session", in any offer or answer from either end. A number the far end gave a
//! codec in an offer we refused still belongs to that codec.
//!
//! An offer numbered from the catalogue (from 96, in order) is right only for the first
//! description: dropping a codec would shift the next one onto its number, and `telephone-event`
//! moves whenever the list before it does. So a call keeps every binding either end wrote, and a
//! changed offer is renumbered against them.

use std::collections::BTreeMap;

use sipral_core::sdp::{MediaDescription, RtpMap, SessionDescription};

use crate::error::MediaError;

/// RFC 3551 §3: the numbers a session binds for itself. Below them the
/// numbers are fixed by the profile, and §8.3.2 has nothing to say.
const DYNAMIC: core::ops::RangeInclusive<u8> = 96..=127;

/// What a binding names, compared the way an `a=rtpmap` line means it.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Meaning {
    /// Folded, because a media subtype name is compared without regard to
    /// case (RFC 6838 §4.2).
    encoding: String,
    clock_rate: u32,
    /// `None` for one channel whether or not it was written, because
    /// RFC 4566 §6 makes one the value an audio stream has when it is not.
    channels: Option<String>,
}

impl Meaning {
    fn of(map: RtpMap) -> Self {
        Self {
            encoding: map.encoding.to_ascii_lowercase(),
            clock_rate: map.clock_rate,
            channels: map.parameters.filter(|channels| channels != "1"),
        }
    }
}

/// Every dynamic number one call's stream has been given, and what it was
/// given to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Payloads {
    bound: BTreeMap<u8, Meaning>,
}

impl Payloads {
    /// Remember what `description` binds on the stream this facade carries.
    ///
    /// The first meaning a number was given stands. A second one is the far
    /// end breaking the rule, and following it would be breaking it too.
    pub(crate) fn note(&mut self, description: &SessionDescription) {
        let Some(stream) = carried(description) else {
            return;
        };
        for number in dynamic_formats(stream) {
            if let Some(map) = stream.rtpmap(number) {
                self.bound.entry(number).or_insert_with(|| Meaning::of(map));
            }
        }
    }

    /// Give each dynamic format of a stream about to be offered the number its codec already has on
    /// this call, and a new codec a number never used on it.
    ///
    /// Formats, `a=rtpmap` and `a=fmtp` lines are renumbered together, so a swap of two numbers
    /// cannot leave lines half-moved.
    ///
    /// # Errors
    ///
    /// [`MediaError::NoPayloadType`] when a new codec finds every dynamic number already bound.
    pub(crate) fn renumber(&self, stream: &mut MediaDescription) -> Result<(), MediaError> {
        let mut moves = BTreeMap::new();
        let mut new = Vec::new();
        for number in dynamic_formats(stream) {
            let Some(meaning) = stream.rtpmap(number).map(Meaning::of) else {
                continue;
            };
            match self.number_of(&meaning) {
                Some(kept) => {
                    moves.insert(number, kept);
                }
                None => new.push(number),
            }
        }
        // a number that is bound is never free, and every number kept above
        // is a bound one, so the two cannot meet
        let mut free = DYNAMIC.filter(|number| !self.bound.contains_key(number));
        for number in new {
            let given = free.next().ok_or(MediaError::NoPayloadType)?;
            moves.insert(number, given);
        }

        for format in &mut stream.formats {
            if let Some(moved) = format.parse().ok().and_then(|number| moves.get(&number)) {
                *format = moved.to_string();
            }
        }
        for attribute in &mut stream.attributes {
            if attribute.name != "rtpmap" && attribute.name != "fmtp" {
                continue;
            }
            let Some(value) = attribute.value.as_mut() else {
                continue;
            };
            let renumbered = {
                let (number, rest) = value.split_once(' ').unwrap_or((value.as_str(), ""));
                number
                    .parse()
                    .ok()
                    .and_then(|number| moves.get(&number))
                    .map(|moved| {
                        if rest.is_empty() {
                            moved.to_string()
                        } else {
                            format!("{moved} {rest}")
                        }
                    })
            };
            if let Some(renumbered) = renumbered {
                *value = renumbered;
            }
        }
        Ok(())
    }

    /// The lowest number bound to `meaning`, when one is. §8.3.2 allows
    /// several numbers for one codec; any of them is a correct answer, and
    /// the lowest is the one two runs agree on.
    fn number_of(&self, meaning: &Meaning) -> Option<u8> {
        self.bound
            .iter()
            .find(|(_, bound)| *bound == meaning)
            .map(|(number, _)| *number)
    }
}

/// The stream this facade negotiates: the first live audio one, which is the
/// one `crate::engine`'s own answer takes.
fn carried(description: &SessionDescription) -> Option<&MediaDescription> {
    description
        .media
        .iter()
        .find(|stream| stream.media == crate::engine::AUDIO && !stream.is_rejected())
}

/// The formats of a stream that are dynamic payload type numbers.
fn dynamic_formats(stream: &MediaDescription) -> impl Iterator<Item = u8> + '_ {
    stream
        .formats
        .iter()
        .filter_map(|format| format.parse().ok())
        .filter(|number| DYNAMIC.contains(number))
}

#[cfg(test)]
mod tests {
    use super::Payloads;
    use crate::error::MediaError;
    use sipral_core::sdp::{Attribute, Connection, MediaDescription, Origin, SessionDescription};
    use std::net::{IpAddr, Ipv4Addr};

    /// One audio stream with these formats and these `a=` lines.
    fn stream(formats: &[&str], lines: &[(&str, &str)]) -> MediaDescription {
        let mut stream = MediaDescription::new(
            "audio",
            4000,
            "RTP/AVP",
            formats.iter().map(|format| (*format).to_owned()).collect(),
        );
        stream.attributes = lines
            .iter()
            .map(|(name, value)| Attribute::with_value(name, value))
            .collect();
        stream
    }

    fn described(stream: MediaDescription) -> SessionDescription {
        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
        let mut description =
            SessionDescription::new(Origin::new(1, 1, address), Connection::new(address));
        description.media.push(stream);
        description
    }

    fn values(stream: &MediaDescription, name: &str) -> Vec<String> {
        stream
            .attributes
            .iter()
            .filter(|attribute| attribute.name == name)
            .filter_map(|attribute| attribute.value.clone())
            .collect()
    }

    #[test]
    fn a_codec_taken_out_of_the_list_does_not_hand_its_number_to_the_next() {
        // the call opened on Opus at 96 and telephone-event at 97; the same
        // catalogue without Opus numbers telephone-event 96, which is Opus's
        let mut call = Payloads::default();
        call.note(&described(stream(
            &["96", "0", "97"],
            &[
                ("rtpmap", "96 opus/48000/2"),
                ("rtpmap", "0 PCMU/8000"),
                ("rtpmap", "97 telephone-event/8000"),
                ("fmtp", "97 0-15"),
            ],
        )));
        let mut offer = stream(
            &["0", "96"],
            &[
                ("rtpmap", "0 PCMU/8000"),
                ("rtpmap", "96 telephone-event/8000"),
                ("fmtp", "96 0-15"),
            ],
        );
        call.renumber(&mut offer)
            .expect("97 is still telephone-event's");
        assert_eq!(offer.formats, ["0", "97"]);
        assert_eq!(
            values(&offer, "rtpmap"),
            ["0 PCMU/8000", "97 telephone-event/8000"]
        );
        assert_eq!(values(&offer, "fmtp"), ["97 0-15"]);
    }

    #[test]
    fn a_codec_new_to_the_call_gets_a_number_nothing_has_had() {
        // 96 went to Opus in an offer the far end wrote, which binds it even
        // though this end never used it; G.722's own number is static
        let mut call = Payloads::default();
        call.note(&described(stream(
            &["96", "101"],
            &[
                ("rtpmap", "96 opus/48000/2"),
                ("rtpmap", "101 telephone-event/48000"),
            ],
        )));
        let mut offer = stream(
            &["96", "9", "97"],
            &[
                ("rtpmap", "96 L16/16000"),
                ("rtpmap", "9 G722/8000"),
                ("rtpmap", "97 telephone-event/16000"),
            ],
        );
        call.renumber(&mut offer).expect("there are numbers left");
        assert_eq!(offer.formats, ["97", "9", "98"]);
        assert_eq!(
            values(&offer, "rtpmap"),
            ["97 L16/16000", "9 G722/8000", "98 telephone-event/16000"]
        );
    }

    #[test]
    fn two_codecs_that_trade_numbers_trade_them_whole() {
        let mut call = Payloads::default();
        call.note(&described(stream(
            &["96", "97"],
            &[
                ("rtpmap", "96 opus/48000/2"),
                ("rtpmap", "97 telephone-event/48000"),
                ("fmtp", "96 useinbandfec=1"),
            ],
        )));
        let mut offer = stream(
            &["96", "97"],
            &[
                ("rtpmap", "96 telephone-event/48000"),
                ("rtpmap", "97 opus/48000/2"),
                ("fmtp", "97 useinbandfec=1"),
                ("fmtp", "96 0-15"),
            ],
        );
        call.renumber(&mut offer).expect("both are bound already");
        assert_eq!(offer.formats, ["97", "96"]);
        assert_eq!(
            values(&offer, "rtpmap"),
            ["97 telephone-event/48000", "96 opus/48000/2"]
        );
        assert_eq!(values(&offer, "fmtp"), ["96 useinbandfec=1", "97 0-15"]);
    }

    #[test]
    fn a_binding_is_the_same_whatever_case_or_channel_count_wrote_it() {
        // "PCMU" and "pcmu" are one subtype, and an audio stream with no
        // channel count has one
        let mut call = Payloads::default();
        call.note(&described(stream(
            &["100"],
            &[("rtpmap", "100 TELEPHONE-EVENT/8000/1")],
        )));
        let mut offer = stream(&["96"], &[("rtpmap", "96 telephone-event/8000")]);
        call.renumber(&mut offer).expect("the same binding");
        assert_eq!(offer.formats, ["100"]);
    }

    #[test]
    fn the_first_meaning_a_number_was_given_is_the_one_that_stands() {
        let mut call = Payloads::default();
        call.note(&described(stream(
            &["96"],
            &[("rtpmap", "96 opus/48000/2")],
        )));
        call.note(&described(stream(
            &["96"],
            &[("rtpmap", "96 telephone-event/8000")],
        )));
        let mut offer = stream(&["96"], &[("rtpmap", "96 telephone-event/8000")]);
        call.renumber(&mut offer).expect("97 is free");
        assert_eq!(offer.formats, ["97"], "96 is still Opus's");
    }

    #[test]
    fn a_call_that_has_bound_every_number_cannot_take_a_new_codec() {
        let mut call = Payloads::default();
        let formats: Vec<String> = (96..=127).map(|number: u8| number.to_string()).collect();
        let lines: Vec<(String, String)> = (96..=127)
            .map(|number: u8| ("rtpmap".to_owned(), format!("{number} X{number}/8000")))
            .collect();
        let formats: Vec<&str> = formats.iter().map(String::as_str).collect();
        let lines: Vec<(&str, &str)> = lines
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        call.note(&described(stream(&formats, &lines)));
        let mut offer = stream(&["96"], &[("rtpmap", "96 opus/48000/2")]);
        assert_eq!(call.renumber(&mut offer), Err(MediaError::NoPayloadType));
    }

    #[test]
    fn the_last_dynamic_number_is_127_and_it_is_given_out() {
        // RFC 3551 §3 leaves 96 to 127 dynamic: with every number below 127 taken, the 32nd codec
        // still gets one. The test above cannot tell whether the range reaches 127
        let mut call = Payloads::default();
        let formats: Vec<String> = (96..=126).map(|number: u8| number.to_string()).collect();
        let lines: Vec<(String, String)> = (96..=126)
            .map(|number: u8| ("rtpmap".to_owned(), format!("{number} X{number}/8000")))
            .collect();
        let formats: Vec<&str> = formats.iter().map(String::as_str).collect();
        let lines: Vec<(&str, &str)> = lines
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        call.note(&described(stream(&formats, &lines)));
        let mut offer = stream(&["96"], &[("rtpmap", "96 opus/48000/2")]);
        call.renumber(&mut offer).expect("127 is still free");
        assert_eq!(offer.formats, ["127"]);
    }

    #[test]
    fn a_static_number_is_left_where_the_profile_put_it() {
        let call = Payloads::default();
        let mut offer = stream(
            &["8", "0"],
            &[("rtpmap", "8 PCMA/8000"), ("rtpmap", "0 PCMU/8000")],
        );
        let before = offer.clone();
        call.renumber(&mut offer).expect("nothing to move");
        assert_eq!(offer, before);
    }
}
