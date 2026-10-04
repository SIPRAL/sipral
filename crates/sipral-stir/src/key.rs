// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A signer's private key, in the forms it is kept in: the bare 32-octet
//! scalar, an `ECPrivateKey` (RFC 5915 §3), or one wrapped in a PKCS #8
//! `PrivateKeyInfo` (RFC 5958 §2, the algorithm identifier of RFC 5480
//! §2.1.1), each as DER or in the PEM of RFC 7468 (`EC PRIVATE KEY`,
//! `PRIVATE KEY`).
//!
//! An encrypted PKCS #8 key (`ENCRYPTED PRIVATE KEY`, RFC 5958 §3) is refused
//! rather than decrypted: the passphrase is the application's, and so is
//! unlocking what it protects.

use zeroize::Zeroizing;

use crate::base64;
use crate::der::{self, INTEGER, SEQUENCE};

/// OCTET STRING (X.690 §8.7).
const OCTET_STRING: u8 = 0x04;
/// OBJECT IDENTIFIER (X.690 §8.19).
const OBJECT_IDENTIFIER: u8 = 0x06;
/// `[0]`, constructed: `ECPrivateKey.parameters`.
const PARAMETERS: u8 = 0xa0;

/// `id-ecPublicKey` (RFC 5480 §2.1.1), as the DER contents of its OBJECT
/// IDENTIFIER: 1.2.840.10045.2.1.
const EC_PUBLIC_KEY: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// `secp256r1` (RFC 5480 §2.1.1.1): 1.2.840.10045.3.1.7.
const SECP256R1: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// The P-256 private key's octets: RFC 5915 §3's `privateKey`, which is
/// `ceiling(log2(n)/8)` octets, thirty-two for this curve.
const SCALAR_LEN: usize = 32;

/// Not a P-256 private key this module can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unreadable;

/// The scalar a key holds, whichever of the forms above it came in.
pub(crate) fn scalar(input: &[u8]) -> Result<[u8; SCALAR_LEN], Unreadable> {
    if let Ok(bare) = <[u8; SCALAR_LEN]>::try_from(input) {
        return Ok(bare);
    }
    if input.first() == Some(&SEQUENCE) {
        return from_der(input);
    }
    let text = std::str::from_utf8(input).map_err(|_| Unreadable)?;
    from_der(&pem(text)?)
}

/// The first PEM block labelled as a private key, decoded.
///
/// The base64 body and the block decoded from it hold the key as much as the
/// scalar does, so both are in buffers that wipe themselves; the body's is
/// as long as the whole text from the start, so it never grows and leaves a
/// copy of what it held behind in memory it gave back.
fn pem(text: &str) -> Result<Zeroizing<Vec<u8>>, Unreadable> {
    let mut lines = text.lines().map(str::trim);
    while let Some(line) = lines.next() {
        let Some(label) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|rest| rest.strip_suffix("-----"))
        else {
            continue;
        };
        let mut body = Zeroizing::new(String::with_capacity(text.len()));
        let mut ended = false;
        for line in lines.by_ref() {
            if let Some(end) = line
                .strip_prefix("-----END ")
                .and_then(|rest| rest.strip_suffix("-----"))
            {
                if end != label {
                    return Err(Unreadable);
                }
                ended = true;
                break;
            }
            body.extend(line.chars().filter(|c| !c.is_ascii_whitespace()));
        }
        if !ended {
            return Err(Unreadable);
        }
        // RFC 5915 §4 and RFC 5958 §5: the only two labels a key in the
        // clear travels under; a certificate or parameters beside it are
        // skipped, and an encrypted key is the passphrase holder's to open
        if label == "EC PRIVATE KEY" || label == "PRIVATE KEY" {
            return base64::decode_standard(body.as_bytes())
                .map(Zeroizing::new)
                .map_err(|_| Unreadable);
        }
    }
    Err(Unreadable)
}

/// The scalar out of an `ECPrivateKey` or a `PrivateKeyInfo` around one.
fn from_der(input: &[u8]) -> Result<[u8; SCALAR_LEN], Unreadable> {
    let outer = der::only(input, SEQUENCE).map_err(|_| Unreadable)?;
    let (version, rest) = der::expect(outer.contents, INTEGER).map_err(|_| Unreadable)?;
    match der::unsigned(version.contents).map_err(|_| Unreadable)? {
        // RFC 5915 §3: `ecPrivkeyVer1`
        1 if rest.first() == Some(&OCTET_STRING) => ec_private_key(rest),
        // RFC 5958 §2: v1, or v2 with the public key beside it
        0 | 1 => private_key_info(rest),
        _ => Err(Unreadable),
    }
}

/// `PrivateKeyInfo` after its version: the algorithm, then the key.
fn private_key_info(rest: &[u8]) -> Result<[u8; SCALAR_LEN], Unreadable> {
    let (algorithm, rest) = der::expect(rest, SEQUENCE).map_err(|_| Unreadable)?;
    let (identifier, parameters) =
        der::expect(algorithm.contents, OBJECT_IDENTIFIER).map_err(|_| Unreadable)?;
    let curve = der::only(parameters, OBJECT_IDENTIFIER).map_err(|_| Unreadable)?;
    if identifier.contents != EC_PUBLIC_KEY || curve.contents != SECP256R1 {
        return Err(Unreadable);
    }
    let (wrapped, _attributes_and_public_key) =
        der::expect(rest, OCTET_STRING).map_err(|_| Unreadable)?;
    // RFC 5480 §2.1.1 names the curve once, in the algorithm; the inner
    // `ECPrivateKey` may name it again, and if it does it names the same one
    let inner = der::only(wrapped.contents, SEQUENCE).map_err(|_| Unreadable)?;
    let (version, rest) = der::expect(inner.contents, INTEGER).map_err(|_| Unreadable)?;
    if der::unsigned(version.contents).map_err(|_| Unreadable)? != 1 {
        return Err(Unreadable);
    }
    ec_private_key(rest)
}

/// `ECPrivateKey` after its version: the key, then the optional curve and
/// public key. A curve named here must be P-256; a key naming none is taken
/// as P-256, since the signer that holds it can sign with nothing else.
fn ec_private_key(rest: &[u8]) -> Result<[u8; SCALAR_LEN], Unreadable> {
    let (key, rest) = der::expect(rest, OCTET_STRING).map_err(|_| Unreadable)?;
    if let Ok((parameters, _)) = der::expect(rest, PARAMETERS) {
        let curve = der::only(parameters.contents, OBJECT_IDENTIFIER).map_err(|_| Unreadable)?;
        if curve.contents != SECP256R1 {
            return Err(Unreadable);
        }
    }
    <[u8; SCALAR_LEN]>::try_from(key.contents).map_err(|_| Unreadable)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCALAR: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef,
        0xf0, 0x02,
    ];

    fn oid(contents: &[u8]) -> Vec<u8> {
        der::write(OBJECT_IDENTIFIER, contents)
    }

    /// RFC 5915 §3, with the optional curve.
    fn sec1(curve: &[u8]) -> Vec<u8> {
        let mut body = der::write(INTEGER, &[1]);
        body.extend(der::write(OCTET_STRING, &SCALAR));
        body.extend(der::write(PARAMETERS, &oid(curve)));
        der::write(SEQUENCE, &body)
    }

    /// RFC 5958 §2 around an `ECPrivateKey` that names no curve.
    fn pkcs8(curve: &[u8]) -> Vec<u8> {
        let mut inner = der::write(INTEGER, &[1]);
        inner.extend(der::write(OCTET_STRING, &SCALAR));
        let inner = der::write(SEQUENCE, &inner);
        let mut algorithm = oid(&EC_PUBLIC_KEY);
        algorithm.extend(oid(curve));
        let mut body = der::write(INTEGER, &[0]);
        body.extend(der::write(SEQUENCE, &algorithm));
        body.extend(der::write(OCTET_STRING, &inner));
        der::write(SEQUENCE, &body)
    }

    fn armoured(label: &str, der: &[u8]) -> String {
        let body = base64::encode_standard(der);
        let mut out = format!("-----BEGIN {label}-----\n");
        for chunk in body.as_bytes().chunks(64) {
            out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
            out.push('\n');
        }
        out.push_str("-----END ");
        out.push_str(label);
        out.push_str("-----\n");
        out
    }

    #[test]
    fn every_form_yields_the_same_scalar() {
        assert_eq!(scalar(&SCALAR), Ok(SCALAR));
        assert_eq!(scalar(&sec1(&SECP256R1)), Ok(SCALAR));
        assert_eq!(scalar(&pkcs8(&SECP256R1)), Ok(SCALAR));
        let sec1_pem = armoured("EC PRIVATE KEY", &sec1(&SECP256R1));
        assert_eq!(scalar(sec1_pem.as_bytes()), Ok(SCALAR));
        // a certificate ahead of the key, as a bundle often has it
        let bundle = format!(
            "{}{}",
            armoured("CERTIFICATE", &[0x30, 0x00]),
            armoured("PRIVATE KEY", &pkcs8(&SECP256R1))
        );
        assert_eq!(scalar(bundle.as_bytes()), Ok(SCALAR));
    }

    #[test]
    fn another_curve_is_refused() {
        // secp384r1, 1.3.132.0.34
        let p384 = [0x2b, 0x81, 0x04, 0x00, 0x22];
        assert_eq!(scalar(&sec1(&p384)), Err(Unreadable));
        assert_eq!(scalar(&pkcs8(&p384)), Err(Unreadable));
    }

    #[test]
    fn an_encrypted_key_or_no_key_is_refused() {
        let encrypted = armoured("ENCRYPTED PRIVATE KEY", &pkcs8(&SECP256R1));
        assert_eq!(scalar(encrypted.as_bytes()), Err(Unreadable));
        assert_eq!(scalar(b"not a key"), Err(Unreadable));
        assert_eq!(scalar(&[0u8; 31]), Err(Unreadable));
        let mismatched = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n";
        assert_eq!(scalar(mismatched.as_bytes()), Err(Unreadable));
    }

    // what wipes the PEM body and the block decoded from it is the type they
    // are held in, since the wipe itself cannot be watched from safe code:
    // held here, so that a change back to a plain Vec does not compile
    #[test]
    fn the_decoded_block_is_held_in_a_buffer_that_wipes_itself() {
        let text = armoured("EC PRIVATE KEY", &sec1(&SECP256R1));
        let decoded: Zeroizing<Vec<u8>> = pem(&text).expect("a key");
        assert_eq!(*decoded, sec1(&SECP256R1));
        assert_eq!(scalar(text.as_bytes()), Ok(SCALAR));
    }
}
