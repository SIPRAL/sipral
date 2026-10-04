// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Base64 in its two alphabets (RFC 4648): base64url without padding, which
//! every JWS segment is written in (RFC 7515 §2), and the standard alphabet
//! with padding, which a PEM block carries (RFC 7468 §3).
//!
//! Decoding is strict. A character outside the alphabet, a length no encoder
//! produces, and leftover bits that are not zero are all refused, so a given
//! byte string has exactly one encoding that decodes to it: RFC 4648 §3.5
//! allows a decoder to reject non-zero pad bits, and a signature check over a
//! token that has several spellings is a check an attacker can play with.

use zeroize::Zeroizing;

/// The URL- and filename-safe alphabet of RFC 4648 §5.
const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// The standard alphabet of RFC 4648 §4.
#[cfg(any(test, feature = "testing"))]
const STANDARD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// The input is not the unpadded or padded Base64 it has to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Invalid;

/// `input` in base64url, unpadded.
pub(crate) fn encode_url(input: &[u8]) -> String {
    encode(input, URL, false)
}

/// `input` in the standard alphabet, padded, as PEM carries it.
#[cfg(any(test, feature = "testing"))]
pub(crate) fn encode_standard(input: &[u8]) -> String {
    encode(input, STANDARD, true)
}

fn encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let word = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        let symbols = chunk.len() + 1;
        for i in 0..4 {
            if i < symbols {
                let index = usize::try_from((word >> (18 - 6 * i)) & 0x3f).unwrap_or(0);
                out.push(char::from(alphabet.get(index).copied().unwrap_or(b'A')));
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// The value of one base64url symbol.
fn url_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'a'..=b'z' => Some(symbol - b'a' + 26),
        b'0'..=b'9' => Some(symbol - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// The value of one symbol of the standard alphabet.
fn standard_value(symbol: u8) -> Option<u8> {
    match symbol {
        b'+' => Some(62),
        b'/' => Some(63),
        b'-' | b'_' => None,
        other => url_value(other),
    }
}

/// Decode unpadded base64url.
pub(crate) fn decode_url(input: &[u8]) -> Result<Vec<u8>, Invalid> {
    decode(input, url_value)
}

/// Decode the standard alphabet, padding required, as a PEM body holds it
/// once its line breaks are gone.
pub(crate) fn decode_standard(input: &[u8]) -> Result<Vec<u8>, Invalid> {
    if !input.len().is_multiple_of(4) {
        return Err(Invalid);
    }
    let body = match input {
        [rest @ .., b'=', b'='] | [rest @ .., b'='] => rest,
        _ => input,
    };
    decode(body, standard_value)
}

fn decode(input: &[u8], value: fn(u8) -> Option<u8>) -> Result<Vec<u8>, Invalid> {
    // one symbol left over carries six bits, which is less than an octet: no
    // encoder writes that
    if input.len() % 4 == 1 {
        return Err(Invalid);
    }
    // wiped if the input turns out not to be base64 part way through: what is
    // decoded may be a private key
    let mut out = Zeroizing::new(Vec::with_capacity(input.len() / 4 * 3 + 2));
    for chunk in input.chunks(4) {
        let mut word = 0u32;
        for &symbol in chunk {
            word = (word << 6) | u32::from(value(symbol).ok_or(Invalid)?);
        }
        let [_, b0, b1, b2] = match chunk.len() {
            4 => word,
            3 => {
                if word & 0x3 != 0 {
                    return Err(Invalid);
                }
                word << 6
            }
            _ => {
                if word & 0xf != 0 {
                    return Err(Invalid);
                }
                word << 12
            }
        }
        .to_be_bytes();
        out.push(b0);
        if chunk.len() > 2 {
            out.push(b1);
        }
        if chunk.len() > 3 {
            out.push(b2);
        }
    }
    // the buffer itself moves out; nothing is copied
    Ok(core::mem::take(&mut *out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_section10_vectors() {
        let vectors: [(&[u8], &str); 7] = [
            (b"", ""),
            (b"f", "Zg=="),
            (b"fo", "Zm8="),
            (b"foo", "Zm9v"),
            (b"foob", "Zm9vYg=="),
            (b"fooba", "Zm9vYmE="),
            (b"foobar", "Zm9vYmFy"),
        ];
        for (plain, encoded) in vectors {
            assert_eq!(encode_standard(plain), encoded);
            assert_eq!(decode_standard(encoded.as_bytes()), Ok(plain.to_vec()));
            let unpadded = encoded.trim_end_matches('=');
            assert_eq!(encode_url(plain), unpadded);
            assert_eq!(decode_url(unpadded.as_bytes()), Ok(plain.to_vec()));
        }
    }

    #[test]
    fn url_alphabet_differs_from_standard() {
        assert_eq!(encode_url(&[0xfb, 0xff]), "-_8");
        assert_eq!(encode_standard(&[0xfb, 0xff]), "+/8=");
        assert_eq!(decode_url(b"-_8"), Ok(vec![0xfb, 0xff]));
        assert_eq!(decode_url(b"+/8"), Err(Invalid));
        assert_eq!(decode_standard(b"-_8="), Err(Invalid));
    }

    #[test]
    fn padding_is_refused_in_base64url() {
        assert_eq!(decode_url(b"Zg=="), Err(Invalid));
    }

    #[test]
    fn padding_is_required_in_the_standard_alphabet() {
        assert_eq!(decode_standard(b"Zg"), Err(Invalid));
        assert_eq!(decode_standard(b"Z==="), Err(Invalid));
        assert_eq!(decode_standard(b"Zg=a"), Err(Invalid));
    }

    #[test]
    fn a_lone_trailing_symbol_is_refused() {
        assert_eq!(decode_url(b"Zm9vY"), Err(Invalid));
        // a lone zero symbol would otherwise read as one more zero octet
        assert_eq!(decode_url(b"Zm9vA"), Err(Invalid));
    }

    #[test]
    fn non_zero_leftover_bits_are_refused() {
        // "Zg" is 'f'; "Zh" carries the same octet with a stray bit after it
        assert_eq!(decode_url(b"Zh"), Err(Invalid));
        assert_eq!(decode_url(b"Zm8"), Ok(b"fo".to_vec()));
        assert_eq!(decode_url(b"Zm9"), Err(Invalid));
    }
}
