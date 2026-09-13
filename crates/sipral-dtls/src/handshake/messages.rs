// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The handshake messages after the hellos, in the forms an ECDHE_ECDSA
//! handshake gives them, ChangeCipherSpec, and one type for any message.
//!
//! ServerKeyExchange and ClientKeyExchange have a structure only once the key
//! exchange is known (RFC 5246 §7.4.3, §7.4.7). The one read here is ECDHE's
//! (RFC 8422 §5.4 and §5.7), the only key exchange this crate negotiates.

use super::HandshakeType;
use super::extensions::{NamedGroup, SignatureAndHash};
use super::hello::{ClientHello, HelloVerifyRequest, ServerHello};
use crate::prf::{RANDOM_LEN, VERIFY_DATA_LEN};
use crate::wire::{self, Reader};
use crate::{Error, ct};

/// `ECCurveType.named_curve` (RFC 8422 §5.4), the only curve type left.
pub const NAMED_CURVE: u8 = 3;

/// `opaque ASN.1Cert<1..2^24-1>` and `certificate_list<0..2^24-1>`.
const CERTIFICATES_MAX: usize = 0xFF_FFFF;

/// `digitally-signed` as TLS 1.2 writes it (RFC 5246 §4.7): the algorithm
/// pair, then `opaque signature<0..2^16-1>` — for ECDSA, a DER
/// `Ecdsa-Sig-Value` (RFC 8422 §5.4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DigitallySigned {
    /// The hash and signature algorithm used.
    pub algorithm: SignatureAndHash,
    /// The signature.
    pub signature: Vec<u8>,
}

impl DigitallySigned {
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let algorithm = SignatureAndHash::from_bytes(r.array()?);
        let signature = r.vec16(0, 0xFFFF)?.to_vec();
        Ok(Self {
            algorithm,
            signature,
        })
    }

    fn write(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        out.extend_from_slice(&self.algorithm.to_bytes());
        wire::put_vec16(out, &self.signature, 0, 0xFFFF)
    }
}

/// Certificate (RFC 5246 §7.4.2): the sender's certificate first, then any
/// chain behind it, each DER.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Certificate {
    /// The certificates, sender's own first. May be empty only in a client's
    /// answer to a CertificateRequest it cannot satisfy.
    pub certificate_list: Vec<Vec<u8>>,
}

impl Certificate {
    /// Read a Certificate body.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] for a length that runs past what holds it,
    /// [`Error::Length`] for an empty certificate, [`Error::TrailingData`]
    /// for octets after the list.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let mut list = Reader::new(r.vec24(0, CERTIFICATES_MAX)?);
        r.finish()?;
        let mut certificate_list = Vec::new();
        while !list.is_empty() {
            certificate_list.push(list.vec24(1, CERTIFICATES_MAX)?.to_vec());
        }
        Ok(Self { certificate_list })
    }

    /// Write the body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for an empty certificate or a list too long for its
    /// length field. Nothing is written on error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::block(out, 3, 0, CERTIFICATES_MAX, |out| {
            for certificate in &self.certificate_list {
                wire::put_vec24(out, certificate, 1, CERTIFICATES_MAX)?;
            }
            Ok(())
        })
    }
}

/// ServerKeyExchange for ECDHE (RFC 8422 §5.4): `ServerECDHParams`, then the
/// signature over them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ServerKeyExchange {
    /// The curve of the ephemeral key.
    pub named_curve: NamedGroup,
    /// `ECPoint.point`: the server's ephemeral public key.
    pub public: Vec<u8>,
    /// The signature over [`ServerKeyExchange::signed_content`].
    pub signed_params: DigitallySigned,
}

impl ServerKeyExchange {
    /// Read a ServerKeyExchange body.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] for any curve type but `named_curve`, whose
    /// explicit alternatives RFC 8422 deprecates and whose structure this
    /// crate does not read; [`Error::Length`] for an empty point; the usual
    /// framing errors otherwise.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        if r.u8()? != NAMED_CURVE {
            return Err(Error::IllegalValue);
        }
        let named_curve = NamedGroup(r.u16()?);
        // opaque point <1..2^8-1>
        let public = r.vec8(1, 0xFF)?.to_vec();
        let signed_params = DigitallySigned::read(&mut r)?;
        r.finish()?;
        Ok(Self {
            named_curve,
            public,
            signed_params,
        })
    }

    /// `ServerECDHParams` in its wire form.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a point that is empty or over 255 octets.
    pub fn params(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(4 + self.public.len());
        self.write_params(&mut out)?;
        Ok(out)
    }

    /// What the server signs: `ClientHello.random + ServerHello.random +
    /// ServerKeyExchange.params` (RFC 8422 §5.4).
    ///
    /// # Errors
    ///
    /// As [`ServerKeyExchange::params`].
    pub fn signed_content(
        &self,
        client_random: &[u8; RANDOM_LEN],
        server_random: &[u8; RANDOM_LEN],
    ) -> Result<Vec<u8>, Error> {
        let mut out = Vec::with_capacity(2 * RANDOM_LEN + 4 + self.public.len());
        out.extend_from_slice(client_random);
        out.extend_from_slice(server_random);
        self.write_params(&mut out)?;
        Ok(out)
    }

    fn write_params(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::put_u8(out, NAMED_CURVE);
        wire::put_u16(out, self.named_curve.0);
        wire::put_vec8(out, &self.public, 1, 0xFF)
    }

    /// Write the body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a point or signature outside its bounds. Nothing
    /// is written on error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::all_or_nothing(out, |out| {
            self.write_params(out)?;
            self.signed_params.write(out)
        })
    }
}

/// CertificateRequest (RFC 5246 §7.4.4, RFC 8422 §5.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateRequest {
    /// `ClientCertificateType` values.
    pub certificate_types: Vec<u8>,
    /// The pairs the server can verify, in descending order of preference.
    pub supported_signature_algorithms: Vec<SignatureAndHash>,
    /// DER distinguished names of acceptable authorities. Empty in DTLS-SRTP,
    /// where there are none.
    pub certificate_authorities: Vec<Vec<u8>>,
}

impl CertificateRequest {
    /// `ecdsa_sign(64)` (RFC 8422 §5.5).
    pub const ECDSA_SIGN: u8 = 64;

    /// Read a CertificateRequest body.
    ///
    /// RFC 5246 prints the signature list's bounds three ways — `<2..2^16-2>`
    /// in §7.4.1.4.1, `<2^16-1>` in §7.4.4, `<2..2^16-1>` in A.4.2. Its
    /// elements are two octets each, so the only lengths all three admit are
    /// the even ones from 2 to 65534, and those are the ones accepted.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for an empty type list, an empty or odd signature
    /// list, or an empty distinguished name; the usual framing errors
    /// otherwise.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let certificate_types = r.vec8(1, 0xFF)?.to_vec();
        let supported_signature_algorithms = wire::elements::<2>(r.vec16(2, 0xFFFF)?)?
            .into_iter()
            .map(SignatureAndHash::from_bytes)
            .collect();
        let mut authorities = Reader::new(r.vec16(0, 0xFFFF)?);
        r.finish()?;
        let mut certificate_authorities = Vec::new();
        while !authorities.is_empty() {
            // opaque DistinguishedName<1..2^16-1>
            certificate_authorities.push(authorities.vec16(1, 0xFFFF)?.to_vec());
        }
        Ok(Self {
            certificate_types,
            supported_signature_algorithms,
            certificate_authorities,
        })
    }

    /// Write the body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a list or name outside its bounds. Nothing is
    /// written on error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::all_or_nothing(out, |out| {
            wire::put_vec8(out, &self.certificate_types, 1, 0xFF)?;
            wire::block(out, 2, 2, 0xFFFE, |out| {
                for pair in &self.supported_signature_algorithms {
                    out.extend_from_slice(&pair.to_bytes());
                }
                Ok(())
            })?;
            wire::block(out, 2, 0, 0xFFFF, |out| {
                for name in &self.certificate_authorities {
                    wire::put_vec16(out, name, 1, 0xFFFF)?;
                }
                Ok(())
            })
        })
    }
}

/// ClientKeyExchange for ECDHE (RFC 8422 §5.7): the client's ephemeral point.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClientKeyExchange {
    /// `ecdh_Yc`: the client's ephemeral public key.
    pub public: Vec<u8>,
}

impl ClientKeyExchange {
    /// Read a ClientKeyExchange body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for an empty point, the usual framing errors
    /// otherwise.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let public = r.vec8(1, 0xFF)?.to_vec();
        r.finish()?;
        Ok(Self { public })
    }

    /// Write the body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a point that is empty or over 255 octets.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::put_vec8(out, &self.public, 1, 0xFF)
    }
}

/// CertificateVerify (RFC 5246 §7.4.8): a signature over the transcript up to
/// this message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CertificateVerify {
    /// The signature.
    pub signed: DigitallySigned,
}

impl CertificateVerify {
    /// Read a CertificateVerify body.
    ///
    /// # Errors
    ///
    /// The usual framing errors.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let signed = DigitallySigned::read(&mut r)?;
        r.finish()?;
        Ok(Self { signed })
    }

    /// Write the body.
    ///
    /// # Errors
    ///
    /// [`Error::Length`] for a signature over 65535 octets. Nothing is
    /// written on error.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        wire::all_or_nothing(out, |out| self.signed.write(out))
    }
}

/// Finished (RFC 5246 §7.4.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Finished {
    /// `verify_data`, twelve octets for every suite that does not say
    /// otherwise.
    pub verify_data: [u8; VERIFY_DATA_LEN],
}

impl Finished {
    /// Read a Finished body, which is exactly twelve octets.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] for fewer, [`Error::TrailingData`] for more.
    pub fn parse(body: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(body);
        let verify_data = r.array()?;
        r.finish()?;
        Ok(Self { verify_data })
    }

    /// Write the body.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.verify_data);
    }

    /// Whether this is the `verify_data` expected, compared without stopping
    /// at the first differing octet: an early exit would tell a forger how
    /// many leading octets it had right.
    #[must_use]
    pub fn matches(&self, expected: &[u8; VERIFY_DATA_LEN]) -> bool {
        ct::equal(&self.verify_data, expected)
    }
}

/// ChangeCipherSpec (RFC 5246 §7.1): "a single byte of value 1", in a record
/// of its own content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChangeCipherSpec;

impl ChangeCipherSpec {
    /// The one octet the message is.
    pub const VALUE: u8 = 1;

    /// Read a ChangeCipherSpec record's fragment.
    ///
    /// # Errors
    ///
    /// [`Error::Truncated`] for an empty fragment, [`Error::IllegalValue`] for
    /// any octet but 1, [`Error::TrailingData`] for more than one.
    pub fn parse(fragment: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(fragment);
        if r.u8()? != Self::VALUE {
            return Err(Error::IllegalValue);
        }
        r.finish()?;
        Ok(Self)
    }

    /// The fragment.
    #[must_use]
    pub const fn encode(self) -> [u8; 1] {
        [Self::VALUE]
    }
}

/// Any handshake message this crate reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeMessage {
    /// HelloRequest, whose body is empty. DTLS-SRTP peers refuse
    /// renegotiation (RFC 8827 §6.5), and so does this crate.
    HelloRequest,
    /// ClientHello.
    ClientHello(ClientHello),
    /// ServerHello.
    ServerHello(ServerHello),
    /// HelloVerifyRequest.
    HelloVerifyRequest(HelloVerifyRequest),
    /// Certificate.
    Certificate(Certificate),
    /// ServerKeyExchange.
    ServerKeyExchange(ServerKeyExchange),
    /// CertificateRequest.
    CertificateRequest(CertificateRequest),
    /// ServerHelloDone, whose body is empty.
    ServerHelloDone,
    /// CertificateVerify.
    CertificateVerify(CertificateVerify),
    /// ClientKeyExchange.
    ClientKeyExchange(ClientKeyExchange),
    /// Finished.
    Finished(Finished),
}

impl HandshakeMessage {
    /// Read the body of a reassembled message of type `msg_type`.
    ///
    /// # Errors
    ///
    /// [`Error::IllegalValue`] for a type this crate does not read — a
    /// NewSessionTicket, for one, which it never asks for — and the errors of
    /// each message's own parser.
    pub fn parse(msg_type: HandshakeType, body: &[u8]) -> Result<Self, Error> {
        Ok(match msg_type {
            HandshakeType::HELLO_REQUEST => {
                Reader::new(body).finish()?;
                Self::HelloRequest
            }
            HandshakeType::CLIENT_HELLO => Self::ClientHello(ClientHello::parse(body)?),
            HandshakeType::SERVER_HELLO => Self::ServerHello(ServerHello::parse(body)?),
            HandshakeType::HELLO_VERIFY_REQUEST => {
                Self::HelloVerifyRequest(HelloVerifyRequest::parse(body)?)
            }
            HandshakeType::CERTIFICATE => Self::Certificate(Certificate::parse(body)?),
            HandshakeType::SERVER_KEY_EXCHANGE => {
                Self::ServerKeyExchange(ServerKeyExchange::parse(body)?)
            }
            HandshakeType::CERTIFICATE_REQUEST => {
                Self::CertificateRequest(CertificateRequest::parse(body)?)
            }
            HandshakeType::SERVER_HELLO_DONE => {
                Reader::new(body).finish()?;
                Self::ServerHelloDone
            }
            HandshakeType::CERTIFICATE_VERIFY => {
                Self::CertificateVerify(CertificateVerify::parse(body)?)
            }
            HandshakeType::CLIENT_KEY_EXCHANGE => {
                Self::ClientKeyExchange(ClientKeyExchange::parse(body)?)
            }
            HandshakeType::FINISHED => Self::Finished(Finished::parse(body)?),
            _ => return Err(Error::IllegalValue),
        })
    }

    /// The type the message is sent under.
    #[must_use]
    pub const fn msg_type(&self) -> HandshakeType {
        match self {
            Self::HelloRequest => HandshakeType::HELLO_REQUEST,
            Self::ClientHello(_) => HandshakeType::CLIENT_HELLO,
            Self::ServerHello(_) => HandshakeType::SERVER_HELLO,
            Self::HelloVerifyRequest(_) => HandshakeType::HELLO_VERIFY_REQUEST,
            Self::Certificate(_) => HandshakeType::CERTIFICATE,
            Self::ServerKeyExchange(_) => HandshakeType::SERVER_KEY_EXCHANGE,
            Self::CertificateRequest(_) => HandshakeType::CERTIFICATE_REQUEST,
            Self::ServerHelloDone => HandshakeType::SERVER_HELLO_DONE,
            Self::CertificateVerify(_) => HandshakeType::CERTIFICATE_VERIFY,
            Self::ClientKeyExchange(_) => HandshakeType::CLIENT_KEY_EXCHANGE,
            Self::Finished(_) => HandshakeType::FINISHED,
        }
    }

    /// Write the body, without the handshake header.
    ///
    /// # Errors
    ///
    /// The errors of the message's own encoder. Nothing is written on error.
    pub fn encode_body(&self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self {
            Self::HelloRequest | Self::ServerHelloDone => Ok(()),
            Self::ClientHello(hello) => hello.encode(out),
            Self::ServerHello(hello) => hello.encode(out),
            Self::HelloVerifyRequest(request) => request.encode(out),
            Self::Certificate(certificate) => certificate.encode(out),
            Self::ServerKeyExchange(exchange) => exchange.encode(out),
            Self::CertificateRequest(request) => request.encode(out),
            Self::CertificateVerify(verify) => verify.encode(out),
            Self::ClientKeyExchange(exchange) => exchange.encode(out),
            Self::Finished(finished) => {
                finished.encode(out);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::extensions::{Extension, Extensions};
    use super::super::hello::{COMPRESSION_NULL, CipherSuite};
    use super::*;
    use crate::Random;
    use crate::keys::{EcdsaKey, EphemeralKey};
    use crate::random::testing::Counter;
    use crate::record::ProtocolVersion;

    fn body_of(message: &HandshakeMessage) -> Vec<u8> {
        let mut out = Vec::new();
        message.encode_body(&mut out).unwrap();
        out
    }

    /// The same message with its extensions block removed, for a hello: the
    /// one shorter body that is still a valid message.
    fn without_extensions(message: &HandshakeMessage) -> Option<HandshakeMessage> {
        match message {
            HandshakeMessage::ClientHello(hello) => {
                Some(HandshakeMessage::ClientHello(ClientHello {
                    extensions: None,
                    ..hello.clone()
                }))
            }
            HandshakeMessage::ServerHello(hello) => {
                Some(HandshakeMessage::ServerHello(ServerHello {
                    extensions: None,
                    ..hello.clone()
                }))
            }
            _ => None,
        }
    }

    /// Reads back to itself, and refuses every shorter body and a longer one
    /// — except, for a hello, the body that stops where its extensions begin.
    fn strict(message: &HandshakeMessage) -> Vec<u8> {
        let body = body_of(message);
        let msg_type = message.msg_type();
        assert_eq!(
            HandshakeMessage::parse(msg_type, &body).as_ref(),
            Ok(message)
        );
        let shorter_valid = without_extensions(message);
        for cut in 0..body.len() {
            match HandshakeMessage::parse(msg_type, &body[..cut]) {
                Err(_) => {}
                Ok(parsed) => assert_eq!(Some(parsed), shorter_valid, "{msg_type:?} cut at {cut}"),
            }
        }
        let mut longer = body.clone();
        longer.push(0);
        assert!(
            HandshakeMessage::parse(msg_type, &longer).is_err(),
            "{msg_type:?} longer"
        );
        body
    }

    fn ske() -> ServerKeyExchange {
        ServerKeyExchange {
            named_curve: NamedGroup::SECP256R1,
            public: vec![4; 65],
            signed_params: DigitallySigned {
                algorithm: SignatureAndHash::ECDSA_SHA256,
                signature: vec![0x30; 70],
            },
        }
    }

    fn every_message() -> Vec<HandshakeMessage> {
        let mut extensions = Extensions::new();
        extensions.push(Extension::ExtendedMasterSecret).unwrap();
        vec![
            HandshakeMessage::HelloRequest,
            HandshakeMessage::ClientHello(ClientHello {
                client_version: ProtocolVersion::DTLS_1_2,
                random: [1; 32],
                session_id: Vec::new(),
                cookie: vec![9; 32],
                cipher_suites: vec![CipherSuite::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
                compression_methods: vec![COMPRESSION_NULL],
                extensions: Some(extensions.clone()),
            }),
            HandshakeMessage::ServerHello(ServerHello {
                server_version: ProtocolVersion::DTLS_1_2,
                random: [2; 32],
                session_id: vec![3; 32],
                cipher_suite: CipherSuite::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                compression_method: COMPRESSION_NULL,
                extensions: Some(extensions),
            }),
            HandshakeMessage::HelloVerifyRequest(HelloVerifyRequest {
                server_version: ProtocolVersion::DTLS_1_0,
                cookie: vec![5; 20],
            }),
            HandshakeMessage::Certificate(Certificate {
                certificate_list: vec![vec![0x30; 300], vec![0x31; 2]],
            }),
            HandshakeMessage::ServerKeyExchange(ske()),
            HandshakeMessage::CertificateRequest(CertificateRequest {
                certificate_types: vec![CertificateRequest::ECDSA_SIGN],
                supported_signature_algorithms: vec![SignatureAndHash::ECDSA_SHA256],
                certificate_authorities: vec![vec![0x30, 0], vec![0x30; 5]],
            }),
            HandshakeMessage::ServerHelloDone,
            HandshakeMessage::CertificateVerify(CertificateVerify {
                signed: DigitallySigned {
                    algorithm: SignatureAndHash::ECDSA_SHA256,
                    signature: vec![0x30; 71],
                },
            }),
            HandshakeMessage::ClientKeyExchange(ClientKeyExchange {
                public: vec![4; 65],
            }),
            HandshakeMessage::Finished(Finished {
                verify_data: [0xF1; 12],
            }),
        ]
    }

    #[test]
    fn every_message_reads_back_to_itself_and_refuses_any_other_length() {
        for message in every_message() {
            strict(&message);
        }
    }

    #[test]
    fn a_type_this_crate_does_not_read_is_refused() {
        // new_session_ticket(4), and a type nobody assigned
        for msg_type in [4, 99, 255] {
            assert_eq!(
                HandshakeMessage::parse(HandshakeType(msg_type), &[]),
                Err(Error::IllegalValue)
            );
        }
    }

    #[test]
    fn server_key_exchange_is_ecdhe_params_then_a_signature() {
        let body = body_of(&HandshakeMessage::ServerKeyExchange(ske()));
        let mut expected = vec![3, 0x00, 0x17, 65];
        expected.extend_from_slice(&[4; 65]);
        expected.extend_from_slice(&[4, 3, 0, 70]);
        expected.extend_from_slice(&[0x30; 70]);
        assert_eq!(body, expected);
        assert_eq!(ske().params().unwrap(), expected[..69]);

        let mut explicit_prime = body.clone();
        explicit_prime[0] = 1;
        assert_eq!(
            ServerKeyExchange::parse(&explicit_prime),
            Err(Error::IllegalValue)
        );
        let mut no_point = vec![3, 0, 23, 0];
        no_point.extend_from_slice(&[4, 3, 0, 0]);
        assert_eq!(ServerKeyExchange::parse(&no_point), Err(Error::Length));
    }

    #[test]
    fn the_server_signs_both_randoms_and_its_params() {
        let mut random = Counter::new(3);
        let certificate_key = EcdsaKey::generate(&mut random).unwrap();
        let ephemeral = EphemeralKey::generate(&mut random).unwrap();
        let mut client_random = [0u8; 32];
        let mut server_random = [0u8; 32];
        random.fill(&mut client_random);
        random.fill(&mut server_random);

        let mut exchange = ServerKeyExchange {
            named_curve: NamedGroup::SECP256R1,
            public: ephemeral.public_key().to_vec(),
            signed_params: DigitallySigned {
                algorithm: SignatureAndHash::ECDSA_SHA256,
                signature: Vec::new(),
            },
        };
        let content = exchange
            .signed_content(&client_random, &server_random)
            .unwrap();
        let mut by_hand = client_random.to_vec();
        by_hand.extend_from_slice(&server_random);
        by_hand.extend_from_slice(&[3, 0, 23, 65]);
        by_hand.extend_from_slice(&ephemeral.public_key());
        assert_eq!(content, by_hand);
        exchange.signed_params.signature = certificate_key.sign(&content).unwrap();

        let mut body = Vec::new();
        exchange.encode(&mut body).unwrap();
        let received = ServerKeyExchange::parse(&body).unwrap();
        let peer = certificate_key.peer_key();
        let signed = received
            .signed_content(&client_random, &server_random)
            .unwrap();
        assert_eq!(
            peer.verify(&signed, &received.signed_params.signature),
            Ok(())
        );
        // the same params under swapped randoms are not what was signed
        let swapped = received
            .signed_content(&server_random, &client_random)
            .unwrap();
        assert_eq!(
            peer.verify(&swapped, &received.signed_params.signature),
            Err(Error::BadSignature)
        );
    }

    #[test]
    fn certificate_lists_are_held_to_their_framing() {
        assert_eq!(
            Certificate::parse(&[0, 0, 0]),
            Ok(Certificate {
                certificate_list: Vec::new()
            })
        );
        // a certificate of no octets
        assert_eq!(Certificate::parse(&[0, 0, 3, 0, 0, 0]), Err(Error::Length));
        // an inner length past the list
        assert_eq!(
            Certificate::parse(&[0, 0, 4, 0, 0, 2, 7]),
            Err(Error::Truncated)
        );
        // a list length past the body
        assert_eq!(
            Certificate::parse(&[0, 0, 9, 0, 0, 1, 7]),
            Err(Error::Truncated)
        );
        // octets after the list
        assert_eq!(
            Certificate::parse(&[0, 0, 4, 0, 0, 1, 7, 0]),
            Err(Error::TrailingData)
        );
        let empty_certificate = Certificate {
            certificate_list: vec![Vec::new()],
        };
        let mut out = vec![0xEE];
        assert_eq!(empty_certificate.encode(&mut out), Err(Error::Length));
        assert_eq!(out, [0xEE]);
    }

    #[test]
    fn certificate_request_fields_are_held_to_their_bounds() {
        let good = [1, 64, 0, 2, 4, 3, 0, 0];
        assert!(CertificateRequest::parse(&good).is_ok());
        assert_eq!(
            CertificateRequest::parse(&[0, 0, 2, 4, 3, 0, 0]),
            Err(Error::Length)
        );
        assert_eq!(
            CertificateRequest::parse(&[1, 64, 0, 0, 0, 0]),
            Err(Error::Length)
        );
        assert_eq!(
            CertificateRequest::parse(&[1, 64, 0, 3, 4, 3, 2, 0, 0]),
            Err(Error::Length)
        );
        assert_eq!(
            CertificateRequest::parse(&[1, 64, 0, 2, 4, 3, 0, 2, 0, 0]),
            Err(Error::Length)
        );
        assert_eq!(
            CertificateRequest::parse(&[1, 64, 0, 2, 4, 3, 0, 3, 0, 5, 1]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn small_messages_are_exactly_their_size() {
        assert_eq!(ClientKeyExchange::parse(&[0]), Err(Error::Length));
        assert_eq!(Finished::parse(&[0; 11]), Err(Error::Truncated));
        assert_eq!(Finished::parse(&[0; 13]), Err(Error::TrailingData));
        assert_eq!(
            HandshakeMessage::parse(HandshakeType::SERVER_HELLO_DONE, &[0]),
            Err(Error::TrailingData)
        );
        assert_eq!(
            HandshakeMessage::parse(HandshakeType::HELLO_REQUEST, &[0]),
            Err(Error::TrailingData)
        );

        assert_eq!(ChangeCipherSpec::parse(&[1]), Ok(ChangeCipherSpec));
        assert_eq!(ChangeCipherSpec.encode(), [1]);
        assert_eq!(ChangeCipherSpec::parse(&[]), Err(Error::Truncated));
        assert_eq!(ChangeCipherSpec::parse(&[2]), Err(Error::IllegalValue));
        assert_eq!(ChangeCipherSpec::parse(&[1, 1]), Err(Error::TrailingData));
    }

    #[test]
    fn finished_matches_only_its_own_verify_data() {
        let finished = Finished {
            verify_data: [0x5A; 12],
        };
        assert!(finished.matches(&[0x5A; 12]));
        for position in 0..12 {
            let mut other = [0x5A; 12];
            other[position] ^= 1;
            assert!(!finished.matches(&other), "octet {position}");
        }
    }

    #[test]
    fn no_input_makes_a_parser_panic() {
        let mut random = Counter::new(0xF022);
        let types: Vec<HandshakeType> = (0..=255u8).map(HandshakeType).collect();
        // two octets that choose a length of at most 255 + 144, then that many
        let mut buffer = [0u8; 2 + 255 + 144];
        for round in 0..3000 {
            random.fill(&mut buffer);
            let len = usize::from(buffer[0]) + usize::from(buffer[1] & 1) * 144;
            let input = &buffer[2..2 + len];
            let msg_type = types[round % types.len()];
            let _ = HandshakeMessage::parse(msg_type, input);
        }
        // every single-octet change to every valid body
        for message in every_message() {
            let body = body_of(&message);
            for position in 0..body.len() {
                for flip in [0x01, 0x80, 0xFF] {
                    let mut mutated = body.clone();
                    mutated[position] ^= flip;
                    let _ = HandshakeMessage::parse(message.msg_type(), &mutated);
                }
            }
        }
    }
}
