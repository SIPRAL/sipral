// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The hello messages: ClientHello with the cookie DTLS adds to it (RFC 6347
//! §4.2.1), ServerHello, and HelloVerifyRequest.

use super::extensions::Extensions;
use crate::Error;
use crate::prf::RANDOM_LEN;
use crate::record::ProtocolVersion;
use crate::wire::{self, Reader};

/// `CipherSuite`, from the IANA TLS Cipher Suites registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CipherSuite(pub u16);

impl CipherSuite {
    /// `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (RFC 5289 §3), the only suite
    /// this crate negotiates.
    pub const ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Self = Self(0xC02B);
    /// `TLS_EMPTY_RENEGOTIATION_INFO_SCSV` (RFC 5746 §3.3): not a suite, but
    /// the same signal as an empty `renegotiation_info` extension.
    pub const EMPTY_RENEGOTIATION_INFO_SCSV: Self = Self(0x00FF);
}

/// `CompressionMethod.null`, which every hello must offer and the only method
/// there is.
pub const COMPRESSION_NULL: u8 = 0;

/// `opaque SessionID<0..32>` (RFC 5246 §7.4.1.2).
pub const MAX_SESSION_ID_LEN: usize = 32;
/// `opaque cookie<0..2^8-1>` (RFC 6347 §4.2.1).
pub const MAX_COOKIE_LEN: usize = 255;

/// ClientHello (RFC 6347 §4.2.1, RFC 5246 §7.4.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientHello {
    /// The highest version the client offers.
    pub client_version: ProtocolVersion,
    /// `ClientHello.random`.
    pub random: [u8; RANDOM_LEN],
    /// The session the client would resume; empty for a new one, which is the
    /// only kind this crate makes.
    pub session_id: Vec<u8>,
    /// Empty in the first ClientHello; the server's cookie in the second.
    pub cookie: Vec<u8>,
    /// In the client's order of preference.
    pub cipher_suites: Vec<CipherSuite>,
    /// In the client's order of preference.
    pub compression_methods: Vec<u8>,
    /// `None` when the message ends after the compression methods, `Some` when
    /// an extensions block follows, even an empty one. RFC 5246 §7.4.1.2 tells
    /// the two apart by whether octets follow, so they are two messages.
    pub extensions: Option<Extensions>,
}

impl ClientHello {
    /// Read a ClientHello body.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] or [`Error::Length`] for a field cut short or out
    /// of its bounds, [`Error::TrailingData`] when octets follow the
    /// extensions — RFC 5246 §7.4.1.2 has the server "check that the amount of
    /// data in the message precisely matches one of these formats" — and any
    /// error of the extensions themselves.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let client_version = ProtocolVersion::read(&mut r)?;
        let random = r.array()?;
        let session_id = r.vec8(0, MAX_SESSION_ID_LEN)?.to_vec();
        let cookie = r.vec8(0, MAX_COOKIE_LEN)?.to_vec();
        // CipherSuite cipher_suites<2..2^16-2>
        let cipher_suites = wire::elements::<2>(r.vec16(2, 0xFFFE)?)?
            .into_iter()
            .map(|pair| CipherSuite(u16::from_be_bytes(pair)))
            .collect();
        // CompressionMethod compression_methods<1..2^8-1>
        let compression_methods = r.vec8(1, 0xFF)?.to_vec();
        let extensions = read_extensions(&mut r)?;
        r.finish()?;
        Ok(Self {
            client_version,
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }

    /// Write the body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a field outside the bounds [`ClientHello::parse`]
    /// holds it to. Nothing is written on error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::all_or_nothing(out, |out| {
            self.client_version.write(out);
            out.extend_from_slice(&self.random);
            wire::put_vec8(out, &self.session_id, 0, MAX_SESSION_ID_LEN)?;
            wire::put_vec8(out, &self.cookie, 0, MAX_COOKIE_LEN)?;
            write_suites(out, &self.cipher_suites)?;
            wire::put_vec8(out, &self.compression_methods, 1, 0xFF)?;
            write_extensions(out, self.extensions.as_ref())
        })
    }

    /// The fields RFC 6347 §4.2.1 requires the client to repeat unchanged when
    /// it answers a HelloVerifyRequest — version, random, session_id,
    /// cipher_suites, compression_methods — in their wire form, which is what
    /// a cookie is computed over.
    pub(crate) fn cookie_input(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::all_or_nothing(out, |out| {
            self.client_version.write(out);
            out.extend_from_slice(&self.random);
            wire::put_vec8(out, &self.session_id, 0, MAX_SESSION_ID_LEN)?;
            write_suites(out, &self.cipher_suites)?;
            wire::put_vec8(out, &self.compression_methods, 1, 0xFF)
        })
    }
}

fn write_suites(out: &mut Vec<u8>, suites: &[CipherSuite]) -> Result<(), Error> {
    wire::block(out, 2, 2, 0xFFFE, |out| {
        for suite in suites {
            wire::put_u16(out, suite.0);
        }
        Ok(())
    })
}

fn read_extensions(r: &mut Reader<'_>) -> Result<Option<Extensions>, Error> {
    if r.is_empty() {
        return Ok(None);
    }
    let block = r.vec16(0, 0xFFFF)?;
    Extensions::parse(block).map(Some)
}

fn write_extensions(out: &mut Vec<u8>, extensions: Option<&Extensions>) -> Result<(), Error> {
    match extensions {
        Some(extensions) => extensions.encode(out),
        None => Ok(()),
    }
}

/// ServerHello (RFC 5246 §7.4.1.3).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerHello {
    /// The version the server chose.
    pub server_version: ProtocolVersion,
    /// `ServerHello.random`.
    pub random: [u8; RANDOM_LEN],
    /// The session's identifier; may be empty.
    pub session_id: Vec<u8>,
    /// The suite chosen from the client's list.
    pub cipher_suite: CipherSuite,
    /// The compression method chosen from the client's list.
    pub compression_method: u8,
    /// As in [`ClientHello::extensions`]: `None` for no block at all.
    pub extensions: Option<Extensions>,
}

impl ServerHello {
    /// Read a ServerHello body.
    ///
    /// # Errors
    ///
    /// As [`ClientHello::parse`].
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let server_version = ProtocolVersion::read(&mut r)?;
        let random = r.array()?;
        let session_id = r.vec8(0, MAX_SESSION_ID_LEN)?.to_vec();
        let cipher_suite = CipherSuite(r.u16()?);
        let compression_method = r.u8()?;
        let extensions = read_extensions(&mut r)?;
        r.finish()?;
        Ok(Self {
            server_version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }

    /// Write the body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a session identifier over 32 octets or an
    /// extension outside its bounds. Nothing is written on error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::all_or_nothing(out, |out| {
            self.server_version.write(out);
            out.extend_from_slice(&self.random);
            wire::put_vec8(out, &self.session_id, 0, MAX_SESSION_ID_LEN)?;
            wire::put_u16(out, self.cipher_suite.0);
            wire::put_u8(out, self.compression_method);
            write_extensions(out, self.extensions.as_ref())
        })
    }
}

/// HelloVerifyRequest (RFC 6347 §4.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HelloVerifyRequest {
    /// §4.2.1: a DTLS 1.2 server "SHOULD use DTLS version 1.0 regardless of
    /// the version of TLS that is expected to be negotiated", and a client
    /// "MUST use the version solely to indicate packet formatting".
    pub server_version: ProtocolVersion,
    /// The cookie the client must echo.
    pub cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    /// Read a HelloVerifyRequest body.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] for a body cut short, [`Error::TrailingData`] for
    /// octets after the cookie.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let server_version = ProtocolVersion::read(&mut r)?;
        let cookie = r.vec8(0, MAX_COOKIE_LEN)?.to_vec();
        r.finish()?;
        Ok(Self {
            server_version,
            cookie,
        })
    }

    /// Write the body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a cookie over 255 octets. Nothing is written on
    /// error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::all_or_nothing(out, |out| {
            self.server_version.write(out);
            wire::put_vec8(out, &self.cookie, 0, MAX_COOKIE_LEN)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::extensions::{Extension, SrtpProtectionProfile, UseSrtp};
    use super::*;

    /// A ClientHello put together by hand in the field order of RFC 6347
    /// §4.3.2, with the extensions of RFC 5246 §7.4.1.4 behind it.
    fn client_hello_bytes() -> Vec<u8> {
        let mut b = vec![254, 253];
        b.extend_from_slice(&[0x11; 32]);
        b.push(0); // no session
        b.extend_from_slice(&[3, 0xC0, 0x0C, 0x1E]); // a three-octet cookie
        b.extend_from_slice(&[0, 4, 0xC0, 0x2B, 0x00, 0xFF]);
        b.extend_from_slice(&[1, 0]); // null compression
        b.extend_from_slice(&[0, 15]); // extensions, fifteen octets
        b.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]); // extended_master_secret
        b.extend_from_slice(&[
            0x00, 0x0e, 0x00, 0x07, 0x00, 0x04, 0x00, 0x01, 0x00, 0x02, 0x00,
        ]); // use_srtp
        b
    }

    fn client_hello() -> ClientHello {
        let mut extensions = Extensions::new();
        extensions.push(Extension::ExtendedMasterSecret).unwrap();
        extensions
            .push(Extension::UseSrtp(UseSrtp {
                profiles: vec![
                    SrtpProtectionProfile::AES128_CM_HMAC_SHA1_80,
                    SrtpProtectionProfile::AES128_CM_HMAC_SHA1_32,
                ],
                mki: Vec::new(),
            }))
            .unwrap();
        ClientHello {
            client_version: ProtocolVersion::DTLS_1_2,
            random: [0x11; 32],
            session_id: Vec::new(),
            cookie: vec![0xC0, 0x0C, 0x1E],
            cipher_suites: vec![
                CipherSuite::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::EMPTY_RENEGOTIATION_INFO_SCSV,
            ],
            compression_methods: vec![COMPRESSION_NULL],
            extensions: Some(extensions),
        }
    }

    #[test]
    fn a_client_hello_reads_and_writes_in_the_order_of_rfc_6347() {
        let bytes = client_hello_bytes();
        assert_eq!(ClientHello::parse(&bytes), Ok(client_hello()));
        let mut out = Vec::new();
        client_hello().encode(&mut out).unwrap();
        assert_eq!(out, bytes);
    }

    #[test]
    fn no_extensions_block_and_an_empty_one_are_different_messages() {
        let mut hello = client_hello();
        hello.extensions = None;
        let mut absent = Vec::new();
        hello.encode(&mut absent).unwrap();
        hello.extensions = Some(Extensions::new());
        let mut empty = Vec::new();
        hello.encode(&mut empty).unwrap();
        assert_eq!(empty.len(), absent.len() + 2);
        assert_eq!(ClientHello::parse(&absent).unwrap().extensions, None);
        assert_eq!(
            ClientHello::parse(&empty).unwrap().extensions,
            Some(Extensions::new())
        );
    }

    #[test]
    fn every_truncation_of_a_client_hello_is_refused_but_the_one_without_extensions() {
        let bytes = client_hello_bytes();
        let without_extensions = bytes.len() - 17;
        for cut in 0..bytes.len() {
            let parsed = ClientHello::parse(&bytes[..cut]);
            if cut == without_extensions {
                assert_eq!(parsed.unwrap().extensions, None);
            } else {
                assert!(parsed.is_err(), "cut at {cut}");
            }
        }
        let mut longer = bytes;
        longer.push(0);
        assert_eq!(ClientHello::parse(&longer), Err(Error::TrailingData));
    }

    #[test]
    fn client_hello_fields_are_held_to_their_bounds() {
        let base = client_hello_bytes();
        let random_end = 2 + 32;

        let mut long_session = base[..random_end].to_vec();
        long_session.push(33);
        long_session.extend_from_slice(&[0; 33]);
        long_session.extend_from_slice(&base[random_end + 1..]);
        assert_eq!(ClientHello::parse(&long_session), Err(Error::Length));

        let suites_at = random_end + 1 + 4;
        let mut odd = base.clone();
        odd[suites_at + 1] = 3;
        assert_eq!(ClientHello::parse(&odd), Err(Error::Length));
        let mut none = base[..suites_at].to_vec();
        none.extend_from_slice(&[0, 0, 1, 0]);
        assert_eq!(ClientHello::parse(&none), Err(Error::Length));

        let compression_at = suites_at + 6;
        let mut no_compression = base[..compression_at].to_vec();
        no_compression.push(0);
        assert_eq!(ClientHello::parse(&no_compression), Err(Error::Length));

        let mut cookie_past_end = base[..=random_end].to_vec();
        cookie_past_end.push(200);
        assert_eq!(ClientHello::parse(&cookie_past_end), Err(Error::Truncated));

        let mut hello = client_hello();
        hello.cookie = vec![0; 256];
        let mut out = vec![0xEE];
        assert_eq!(hello.encode(&mut out), Err(Error::Length));
        hello.cookie.clear();
        hello.cipher_suites.clear();
        assert_eq!(hello.encode(&mut out), Err(Error::Length));
        assert_eq!(out, [0xEE]);
    }

    fn server_hello_bytes() -> Vec<u8> {
        let mut b = vec![254, 253];
        b.extend_from_slice(&[0x22; 32]);
        b.extend_from_slice(&[4, 1, 2, 3, 4]);
        b.extend_from_slice(&[0xC0, 0x2B, 0]);
        b.extend_from_slice(&[0, 5, 0xff, 0x01, 0x00, 0x01, 0x00]);
        b
    }

    #[test]
    fn a_server_hello_reads_writes_and_refuses_what_is_malformed() {
        let bytes = server_hello_bytes();
        let hello = ServerHello::parse(&bytes).unwrap();
        assert_eq!(hello.server_version, ProtocolVersion::DTLS_1_2);
        assert_eq!(hello.random, [0x22; 32]);
        assert_eq!(hello.session_id, [1, 2, 3, 4]);
        assert_eq!(
            hello.cipher_suite,
            CipherSuite::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        );
        assert_eq!(hello.compression_method, COMPRESSION_NULL);
        assert_eq!(
            hello.extensions.as_ref().unwrap().renegotiation_info(),
            Some(&[][..])
        );
        let mut out = Vec::new();
        hello.encode(&mut out).unwrap();
        assert_eq!(out, bytes);

        let without_extensions = bytes.len() - 7;
        for cut in 0..bytes.len() {
            let parsed = ServerHello::parse(&bytes[..cut]);
            assert_eq!(parsed.is_ok(), cut == without_extensions, "cut at {cut}");
        }
        let mut longer = bytes.clone();
        longer.push(1);
        assert_eq!(ServerHello::parse(&longer), Err(Error::TrailingData));

        let mut long_session = hello;
        long_session.session_id = vec![0; 33];
        assert_eq!(long_session.encode(&mut Vec::new()), Err(Error::Length));
        let mut bad = bytes;
        bad[34] = 33;
        assert_eq!(ServerHello::parse(&bad), Err(Error::Length));
    }

    #[test]
    fn a_hello_verify_request_carries_a_version_and_a_cookie() {
        // RFC 6347 §4.2.1: the server "SHOULD use DTLS version 1.0"
        let bytes = [254, 255, 4, 0xDE, 0xAD, 0xBE, 0xEF];
        let request = HelloVerifyRequest::parse(&bytes).unwrap();
        assert_eq!(request.server_version, ProtocolVersion::DTLS_1_0);
        assert_eq!(request.cookie, [0xDE, 0xAD, 0xBE, 0xEF]);
        let mut out = Vec::new();
        request.encode(&mut out).unwrap();
        assert_eq!(out, bytes);

        for cut in 0..bytes.len() {
            assert_eq!(
                HelloVerifyRequest::parse(&bytes[..cut]),
                Err(Error::Truncated),
                "cut at {cut}"
            );
        }
        assert_eq!(
            HelloVerifyRequest::parse(&[254, 255, 0, 9]),
            Err(Error::TrailingData)
        );
        let longest = [&[254, 255, 255][..], &[7; 255]].concat();
        assert_eq!(
            HelloVerifyRequest::parse(&longest).unwrap().cookie.len(),
            255
        );
        let too_long = HelloVerifyRequest {
            server_version: ProtocolVersion::DTLS_1_0,
            cookie: vec![0; 256],
        };
        assert_eq!(too_long.encode(&mut Vec::new()), Err(Error::Length));
    }
}
