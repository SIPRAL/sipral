// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! HPACK (RFC 7541), as much as one request needs.
//!
//! Writing, every field goes out as a literal without indexing and without
//! Huffman coding (§6.2.2): the request is the only one on its connection,
//! so there is nothing for a dynamic table to save, and Apple asks for the
//! two fields that carry a secret -- `:path` names the device and
//! `authorization` the provider token -- to be kept out of its table anyway.
//! Reading has to take whatever the server chose: indexed fields, literals
//! with and without indexing, the dynamic table and its size updates, and
//! Huffman-coded strings.

use std::collections::HashMap;
use std::sync::OnceLock;

/// The static table, Appendix A: index 1 first.
const STATIC: [(&str, &str); 61] = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// The Huffman code, Appendix B: for each symbol 0 to 256 (EOS), the code
/// aligned to the least significant bit, and its length in bits. Written as
/// the RFC's "code as hex" column writes them, so the two read side by side.
#[allow(clippy::unreadable_literal)]
const HUFFMAN: [(u32, u8); 257] = [
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];

/// The symbol 256, which a string never contains (§5.2).
const EOS: u16 = 256;

fn decoding_table() -> &'static HashMap<(u8, u32), u16> {
    static TABLE: OnceLock<HashMap<(u8, u32), u16>> = OnceLock::new();
    TABLE.get_or_init(|| {
        HUFFMAN
            .iter()
            .zip(0u16..)
            .map(|(&(code, bits), symbol)| ((bits, code), symbol))
            .collect()
    })
}

/// A Huffman-coded string decoded, or `None` for one §5.2 forbids: EOS
/// inside it, or padding longer than seven bits or not all ones.
fn huffman_decode(input: &[u8]) -> Option<Vec<u8>> {
    let table = decoding_table();
    let mut out = Vec::new();
    let mut code: u32 = 0;
    let mut bits: u8 = 0;
    for byte in input {
        for shift in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> shift) & 1);
            bits += 1;
            if let Some(&symbol) = table.get(&(bits, code)) {
                if symbol == EOS {
                    return None;
                }
                out.push(u8::try_from(symbol).ok()?);
                code = 0;
                bits = 0;
            } else if bits >= 30 {
                return None;
            }
        }
    }
    let padding_ok = bits < 8 && code == (1u32 << bits) - 1;
    padding_ok.then_some(out)
}

/// An integer with an `n`-bit prefix (§5.1), the prefix's other bits `flags`.
fn put_integer(out: &mut Vec<u8>, value: usize, n: u8, flags: u8) {
    let max = (1usize << n) - 1;
    if value < max {
        out.push(flags | u8::try_from(value).unwrap_or(0));
        return;
    }
    out.push(flags | u8::try_from(max).unwrap_or(0));
    let mut rest = value - max;
    while rest >= 128 {
        out.push(u8::try_from(rest % 128).unwrap_or(0) | 0x80);
        rest /= 128;
    }
    out.push(u8::try_from(rest).unwrap_or(0));
}

fn put_string(out: &mut Vec<u8>, text: &[u8]) {
    put_integer(out, text.len(), 7, 0);
    out.extend_from_slice(text);
}

/// A header block: every field a literal without indexing, new name (§6.2.2).
pub(crate) fn encode(fields: &[(&str, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in fields {
        out.push(0);
        put_string(&mut out, name.as_bytes());
        put_string(&mut out, value.as_bytes());
    }
    out
}

/// Why a header block could not be read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Malformed;

/// One end's decoding context: the dynamic table, newest first (§2.3.2).
pub(crate) struct Decoder {
    table: Vec<(String, String)>,
    size: usize,
    max: usize,
    limit: usize,
}

impl Decoder {
    /// A decoder whose table may hold `limit` octets, the
    /// `SETTINGS_HEADER_TABLE_SIZE` this end announced.
    pub(crate) const fn new(limit: usize) -> Self {
        Self {
            table: Vec::new(),
            size: 0,
            max: limit,
            limit,
        }
    }

    fn evict(&mut self) {
        while self.size > self.max {
            let Some((name, value)) = self.table.pop() else {
                self.size = 0;
                break;
            };
            self.size -= name.len() + value.len() + 32;
        }
    }

    fn insert(&mut self, name: String, value: String) {
        let size = name.len() + value.len() + 32;
        self.table.insert(0, (name, value));
        self.size += size;
        self.evict();
    }

    fn entry(&self, index: usize) -> Option<(String, String)> {
        if index == 0 {
            return None;
        }
        if let Some((name, value)) = STATIC.get(index - 1) {
            return Some(((*name).to_owned(), (*value).to_owned()));
        }
        self.table.get(index - 62).cloned()
    }

    /// Every field of one header block, in order.
    pub(crate) fn decode(&mut self, block: &[u8]) -> Result<Vec<(String, String)>, Malformed> {
        let mut reader = Reader {
            bytes: block,
            at: 0,
        };
        let mut fields = Vec::new();
        while let Some(first) = reader.peek() {
            if first & 0x80 != 0 {
                // §6.1: indexed
                let index = reader.integer(7)?;
                fields.push(self.entry(index).ok_or(Malformed)?);
            } else if first & 0xC0 == 0x40 {
                // §6.2.1: literal with incremental indexing
                let index = reader.integer(6)?;
                let field = self.literal(&mut reader, index)?;
                self.insert(field.0.clone(), field.1.clone());
                fields.push(field);
            } else if first & 0xE0 == 0x20 {
                // §6.3: dynamic table size update
                let max = reader.integer(5)?;
                if max > self.limit {
                    return Err(Malformed);
                }
                self.max = max;
                self.evict();
            } else {
                // §6.2.2 and §6.2.3: literal without indexing, never indexed
                let index = reader.integer(4)?;
                fields.push(self.literal(&mut reader, index)?);
            }
        }
        Ok(fields)
    }

    fn literal(
        &self,
        reader: &mut Reader<'_>,
        index: usize,
    ) -> Result<(String, String), Malformed> {
        let name = if index == 0 {
            reader.string()?
        } else {
            self.entry(index).ok_or(Malformed)?.0
        };
        Ok((name, reader.string()?))
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn byte(&mut self) -> Result<u8, Malformed> {
        let byte = self.peek().ok_or(Malformed)?;
        self.at += 1;
        Ok(byte)
    }

    fn integer(&mut self, n: u8) -> Result<usize, Malformed> {
        let max = (1usize << n) - 1;
        let mut value = usize::from(self.byte()?) & max;
        if value < max {
            return Ok(value);
        }
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            if shift > 28 {
                return Err(Malformed);
            }
            value += (usize::from(byte) & 0x7F) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    fn string(&mut self) -> Result<String, Malformed> {
        let huffman = self.peek().ok_or(Malformed)? & 0x80 != 0;
        let length = self.integer(7)?;
        let end = self.at.checked_add(length).ok_or(Malformed)?;
        let raw = self.bytes.get(self.at..end).ok_or(Malformed)?;
        self.at = end;
        let bytes = if huffman {
            huffman_decode(raw).ok_or(Malformed)?
        } else {
            raw.to_vec()
        };
        String::from_utf8(bytes).map_err(|_| Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text.bytes().filter(u8::is_ascii_hexdigit).collect();
        digits
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0)
            })
            .collect()
    }

    fn fields(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn the_code_is_complete() {
        // a canonical prefix code: the lengths fill the space exactly
        let total: f64 = HUFFMAN
            .iter()
            .map(|&(_, bits)| (-f64::from(bits)).exp2())
            .sum();
        assert!((total - 1.0).abs() < 1e-12);
        assert_eq!(decoding_table().len(), 257);
    }

    #[test]
    fn appendix_c_1_integers() {
        let mut out = Vec::new();
        put_integer(&mut out, 10, 5, 0);
        assert_eq!(out, [0x0a]);
        out.clear();
        put_integer(&mut out, 1337, 5, 0);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        let mut reader = Reader { bytes: &out, at: 0 };
        assert_eq!(reader.integer(5), Ok(1337));
    }

    #[test]
    fn appendix_c_4_requests_with_huffman() {
        let mut decoder = Decoder::new(4096);
        let first = decoder
            .decode(&hex("8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff"))
            .expect("first");
        assert_eq!(
            first,
            fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com")
            ])
        );
        let second = decoder
            .decode(&hex("8286 84be 5886 a8eb 1064 9cbf"))
            .expect("second");
        assert_eq!(
            second,
            fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache")
            ])
        );
        let third = decoder
            .decode(&hex(
                "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
            ))
            .expect("third");
        assert_eq!(
            third,
            fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value")
            ])
        );
    }

    #[test]
    fn appendix_c_6_responses_with_huffman_and_eviction() {
        let mut decoder = Decoder::new(256);
        let first = decoder
            .decode(&hex(
                "4882 6402 5885 aec3 771a 4b61 96d0 7abe 9410 54d4 44a8 2005 9504 0b81 66e0 82a6 \
                 2d1b ff6e 919d 29ad 1718 63c7 8f0b 97c8 e9ae 82ae 43d3",
            ))
            .expect("first");
        assert_eq!(
            first,
            fields(&[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com")
            ])
        );
        let second = decoder.decode(&hex("4883 640e ffc1 c0bf")).expect("second");
        assert_eq!(second[0], (":status".to_owned(), "307".to_owned()));
        let third = decoder
            .decode(&hex(
                "88c1 6196 d07a be94 1054 d444 a820 0595 040b 8166 e084 a62d 1bff c05a 839b d9ab \
                 77ad 94e7 821d d7f2 e6c7 b335 dfdf cd5b 3960 d5af 2708 7f36 72c1 ab27 0fb5 291f \
                 9587 3160 65c0 03ed 4ee5 b106 3d50 07",
            ))
            .expect("third");
        assert_eq!(
            third,
            fields(&[
                (":status", "200"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
                (
                    "set-cookie",
                    "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"
                )
            ])
        );
        assert!(decoder.size <= 256);
    }

    #[test]
    fn what_this_end_writes_reads_back() {
        let block = encode(&[(":method", "POST"), ("apns-topic", "org.example.app.voip")]);
        let mut decoder = Decoder::new(4096);
        assert_eq!(
            decoder.decode(&block).expect("reads"),
            fields(&[(":method", "POST"), ("apns-topic", "org.example.app.voip")])
        );
        assert!(decoder.table.is_empty(), "nothing indexed");
    }

    #[test]
    fn bad_padding_and_bad_indices_are_refused() {
        // "a" is 00011, padded with zeros instead of ones
        assert_eq!(huffman_decode(&[0b0001_1000]), None);
        assert_eq!(huffman_decode(&[0b0001_1111]), Some(b"a".to_vec()));
        let mut decoder = Decoder::new(4096);
        assert_eq!(decoder.decode(&[0xbe]), Err(Malformed));
        // a table size update past the 4096 this end allowed
        assert_eq!(decoder.decode(&[0x3f, 0xe2, 0x1f]), Err(Malformed));
    }
}
