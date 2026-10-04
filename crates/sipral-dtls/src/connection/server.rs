// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The server's side: the stateless cookie exchange, flights 2, 4 and 6 of
//! RFC 6347 §4.2.4, and what it checks in the client's.

use std::mem;
use std::time::Instant;

use super::{Core, Failure, SUITE};
use crate::handshake::{
    self, COMPRESSION_NULL, CertificateRequest, CipherSuite, ClientHello, CookieSecret,
    DigitallySigned, EcPointFormat, Extension, Extensions, Finished, Fragment, HandshakeMessage,
    HandshakeType, HelloVerifyRequest, Message, NamedGroup, Reassembler, ServerHello,
    ServerKeyExchange, SignatureAndHash, SrtpProtectionProfile, Transcript, UseSrtp,
};
use crate::keys::{CertifiedKey, EphemeralKey};
use crate::prf::{MasterSecret, RANDOM_LEN};
use crate::record::{ProtocolVersion, WriteEpoch};
use crate::{Error, Random, Role};

/// The highest ClientHello record sequence number this server starts its own
/// epoch 0 at: 2^47, leaving 2^47 numbers above it.
const MAX_INITIAL_SEQUENCE: u64 = 1 << 47;

/// The message the server is waiting for, with what it has learned so far.
enum Step {
    /// A ClientHello, with nothing held for anyone.
    Listening,
    Certificate {
        client_random: [u8; RANDOM_LEN],
        profile: SrtpProtectionProfile,
    },
    ClientKeyExchange {
        client_random: [u8; RANDOM_LEN],
        profile: SrtpProtectionProfile,
        peer: CertifiedKey,
    },
    CertificateVerify {
        profile: SrtpProtectionProfile,
        peer: CertifiedKey,
        master: MasterSecret,
    },
    Finished {
        profile: SrtpProtectionProfile,
        master: MasterSecret,
    },
    Done,
}

/// What the ClientHello settled, beside the profile.
struct Answer {
    profile: SrtpProtectionProfile,
    /// RFC 5746 §3.6: echo an empty `renegotiation_info` when the client
    /// signalled support by either means.
    secure_renegotiation: bool,
    /// RFC 8422 §5.2: answer `ec_point_formats` when the client sent it.
    point_formats: bool,
}

pub(super) struct Server {
    random: [u8; RANDOM_LEN],
    ephemeral: Option<EphemeralKey>,
    cookie: CookieSecret,
    step: Step,
}

impl Server {
    pub(super) fn new<R: Random + ?Sized>(random: &mut R) -> Result<Self, Error> {
        let mut server_random = [0u8; RANDOM_LEN];
        random.fill(&mut server_random);
        let ephemeral = EphemeralKey::generate(random)?;
        Ok(Self {
            random: server_random,
            ephemeral: Some(ephemeral),
            cookie: CookieSecret::generate(random),
            step: Step::Listening,
        })
    }

    pub(super) const fn is_listening(&self) -> bool {
        matches!(self.step, Step::Listening)
    }

    /// Whether the client's CertificateVerify is verified and its Finished is
    /// all that is left.
    pub(super) const fn awaits_finished(&self) -> bool {
        matches!(self.step, Step::Finished { .. })
    }

    /// A fragment arriving before any ClientHello has been accepted.
    ///
    /// Nothing is kept for it unless it is a whole ClientHello that parses and,
    /// with the cookie exchange on, carries the cookie this server made for it.
    /// Anything else is discarded or answered statelessly, so no error comes
    /// out of here until a ClientHello has been accepted.
    pub(super) fn listen(
        &mut self,
        core: &mut Core,
        record_sequence: u64,
        fragment: &Fragment<'_>,
        now: Instant,
    ) -> Result<(), Failure> {
        let header = fragment.header;
        if header.msg_type != HandshakeType::CLIENT_HELLO
            || header.fragment_offset != 0
            || header.fragment_length != header.length
        {
            return Ok(());
        }
        let Ok(hello) = ClientHello::parse(fragment.body) else {
            return Ok(());
        };
        if core.settings.cookie_exchange && !self.cookie.verify(&[], &hello) {
            self.hello_verify_request(core, record_sequence, header.message_seq, &hello);
            return Ok(());
        }
        let Some(next) = header.message_seq.checked_add(1) else {
            return Ok(());
        };

        // state from here on
        core.reassembler = Reassembler::expecting(core.settings.limits, next);
        // RFC 6347 §4.2.2's example: the server's first message after a cookie
        // exchange is numbered as the ClientHello that carried the cookie
        core.send_seq = header.message_seq;
        // §4.2.1: "the server MUST use the record sequence number in the
        // ClientHello as the record sequence number in its initial
        // ServerHello". The client picks that number, and one near the top
        // of the 48-bit space would leave this end's epoch 0 without the
        // numbers its flights and their retransmissions need; refused above
        // half of it, where no client counting up from zero ever gets
        if record_sequence > MAX_INITIAL_SEQUENCE {
            return Err(Failure::IllegalParameter);
        }
        core.writer.epoch0 = WriteEpoch::starting_at(record_sequence).map_err(Failure::Internal)?;
        core.transcript = Transcript::new();
        core.transcript
            .add(
                HandshakeType::CLIENT_HELLO,
                header.message_seq,
                fragment.body,
            )
            .map_err(Failure::Internal)?;
        let answer = Self::negotiate(core, &hello)?;
        self.hello_flight(core, &hello, &answer, now)
    }

    /// A HelloVerifyRequest, kept nowhere: answered afresh for every
    /// ClientHello without a valid cookie, under the ClientHello's own record
    /// and message sequence numbers (§4.2.1, §4.2.2).
    fn hello_verify_request(
        &self,
        core: &mut Core,
        record_sequence: u64,
        message_seq: u16,
        hello: &ClientHello,
    ) {
        let Ok(cookie) = self.cookie.cookie(&[], hello) else {
            return;
        };
        let request = HelloVerifyRequest {
            server_version: ProtocolVersion::DTLS_1_0,
            cookie: cookie.to_vec(),
        };
        let mut body = Vec::new();
        let mut fragment = Vec::new();
        if request.encode(&mut body).is_ok()
            && handshake::encode_message(
                HandshakeType::HELLO_VERIFY_REQUEST,
                message_seq,
                &body,
                &mut fragment,
            )
            .is_ok()
        {
            let _unsent = core.writer.stateless(record_sequence, &fragment);
        }
    }

    /// Hold a ClientHello to what DTLS-SRTP needs.
    fn negotiate(core: &Core, hello: &ClientHello) -> Result<Answer, Failure> {
        let version = hello.client_version;
        // DTLS versions count down: 1.0 is {254, 255}, 1.2 {254, 253}
        if version.major != ProtocolVersion::DTLS_1_2.major
            || version.minor > ProtocolVersion::DTLS_1_2.minor
        {
            return Err(Failure::ProtocolVersion);
        }
        if !hello.cipher_suites.contains(&SUITE) {
            return Err(Failure::NoCommonParameters);
        }
        // RFC 5246 §7.4.1.2: the list "MUST contain" the null method
        if !hello.compression_methods.contains(&COMPRESSION_NULL) {
            return Err(Failure::IllegalParameter);
        }
        let extensions = hello
            .extensions
            .as_ref()
            .ok_or(Failure::NoExtendedMasterSecret)?;
        if !extensions.extended_master_secret() {
            return Err(Failure::NoExtendedMasterSecret);
        }
        let renegotiation = extensions.renegotiation_info();
        if renegotiation.is_some_and(|connection| !connection.is_empty()) {
            return Err(Failure::Renegotiation);
        }
        if extensions
            .supported_groups()
            .is_some_and(|groups| !groups.contains(&NamedGroup::SECP256R1))
            // RFC 5246 §7.4.1.4.1: a client without the extension verifies
            // SHA-1 only, and this server signs with SHA-256
            || !extensions
                .signature_algorithms()
                .is_some_and(|pairs| pairs.contains(&SignatureAndHash::ECDSA_SHA256))
        {
            return Err(Failure::NoCommonParameters);
        }
        // RFC 8422 §5.1.2: a list without the uncompressed format is refused
        // with illegal_parameter
        let point_formats = extensions.ec_point_formats();
        if point_formats.is_some_and(|formats| !formats.contains(&EcPointFormat::UNCOMPRESSED)) {
            return Err(Failure::IllegalParameter);
        }
        let offered = extensions.use_srtp().ok_or(Failure::NoSrtpProfile)?;
        // this end's order of preference, among what the client offered
        let profile = core
            .settings
            .srtp_profiles
            .iter()
            .copied()
            .find(|profile| offered.profiles.contains(profile))
            .ok_or(Failure::NoSrtpProfile)?;
        Ok(Answer {
            profile,
            secure_renegotiation: renegotiation.is_some()
                || hello
                    .cipher_suites
                    .contains(&CipherSuite::EMPTY_RENEGOTIATION_INFO_SCSV),
            point_formats: point_formats.is_some(),
        })
    }

    /// Flight 4: ServerHello, Certificate, ServerKeyExchange,
    /// CertificateRequest, ServerHelloDone.
    fn hello_flight(
        &mut self,
        core: &mut Core,
        hello: &ClientHello,
        answer: &Answer,
        now: Instant,
    ) -> Result<(), Failure> {
        let mut flight = Vec::with_capacity(5);

        let mut body = Vec::new();
        ServerHello {
            server_version: ProtocolVersion::DTLS_1_2,
            random: self.random,
            session_id: Vec::new(),
            cipher_suite: SUITE,
            compression_method: COMPRESSION_NULL,
            extensions: Some(answered(answer).map_err(Failure::Internal)?),
        }
        .encode(&mut body)
        .map_err(Failure::Internal)?;
        flight.push(core.message(HandshakeType::SERVER_HELLO, body)?);

        let mut body = Vec::new();
        handshake::Certificate {
            certificate_list: vec![core.settings.certificate.clone()],
        }
        .encode(&mut body)
        .map_err(Failure::Internal)?;
        flight.push(core.message(HandshakeType::CERTIFICATE, body)?);

        let public = self
            .ephemeral
            .as_ref()
            .ok_or(Failure::Internal(Error::IllegalValue))?
            .public_key();
        let mut exchange = ServerKeyExchange {
            named_curve: NamedGroup::SECP256R1,
            public: public.to_vec(),
            signed_params: DigitallySigned {
                algorithm: SignatureAndHash::ECDSA_SHA256,
                signature: Vec::new(),
            },
        };
        let content = exchange
            .signed_content(&hello.random, &self.random)
            .map_err(Failure::Internal)?;
        exchange.signed_params.signature = core
            .settings
            .key
            .sign(&content)
            .map_err(Failure::Internal)?;
        let mut body = Vec::new();
        exchange.encode(&mut body).map_err(Failure::Internal)?;
        flight.push(core.message(HandshakeType::SERVER_KEY_EXCHANGE, body)?);

        // RFC 5764 §4.1: in DTLS-SRTP the CertificateRequest "will be sent".
        // Either kind of key the client may certify with: the suite binds
        // only the server's, and a client left as FreeSWITCH ships holds an
        // RSA one, which it withholds — an empty Certificate, and no way to
        // key the call — from a request that names ECDSA alone
        let mut body = Vec::new();
        CertificateRequest {
            certificate_types: vec![CertificateRequest::ECDSA_SIGN, CertificateRequest::RSA_SIGN],
            supported_signature_algorithms: vec![
                SignatureAndHash::ECDSA_SHA256,
                SignatureAndHash::RSA_PKCS1_SHA256,
            ],
            certificate_authorities: Vec::new(),
        }
        .encode(&mut body)
        .map_err(Failure::Internal)?;
        flight.push(core.message(HandshakeType::CERTIFICATE_REQUEST, body)?);

        flight.push(core.message(HandshakeType::SERVER_HELLO_DONE, Vec::new())?);

        self.step = Step::Certificate {
            client_random: hello.random,
            profile: answer.profile,
        };
        core.send_flight(flight, true, now)
    }

    pub(super) fn on_message(
        &mut self,
        core: &mut Core,
        message: &Message,
        now: Instant,
    ) -> Result<(), Failure> {
        let parsed =
            HandshakeMessage::parse(message.msg_type, &message.body).map_err(Failure::Malformed)?;
        match (mem::replace(&mut self.step, Step::Done), parsed) {
            (
                Step::Certificate {
                    client_random,
                    profile,
                },
                HandshakeMessage::Certificate(certificate),
            ) => {
                let peer = core.peer_key(&certificate)?;
                core.transcribe(message)?;
                self.step = Step::ClientKeyExchange {
                    client_random,
                    profile,
                    peer,
                };
                Ok(())
            }
            // RFC 5763 §5 authenticates both ends
            (Step::Certificate { .. }, HandshakeMessage::ClientKeyExchange(_)) => {
                Err(Failure::NoCertificate)
            }
            (
                Step::ClientKeyExchange {
                    client_random,
                    profile,
                    peer,
                },
                HandshakeMessage::ClientKeyExchange(exchange),
            ) => {
                let ephemeral = self
                    .ephemeral
                    .take()
                    .ok_or(Failure::Internal(Error::IllegalValue))?;
                let pre_master = ephemeral
                    .agree(&exchange.public)
                    .map_err(|_| Failure::IllegalParameter)?;
                core.transcribe(message)?;
                let master = MasterSecret::extended(
                    pre_master.as_bytes(),
                    &core.transcript.hash(),
                    client_random,
                    self.random,
                );
                core.install_keys(&master)?;
                self.step = Step::CertificateVerify {
                    profile,
                    peer,
                    master,
                };
                Ok(())
            }
            (
                Step::CertificateVerify {
                    profile,
                    peer,
                    master,
                },
                HandshakeMessage::CertificateVerify(verify),
            ) => {
                // RFC 5246 §7.4.8: one of the pairs the request named, which
                // for each kind of key is exactly one
                if verify.signed.algorithm != peer.algorithm() {
                    return Err(Failure::IllegalParameter);
                }
                peer.verify_digest(
                    verify.signed.algorithm,
                    &core.transcript.hash(),
                    &verify.signed.signature,
                )
                .map_err(|_| Failure::BadSignature)?;
                core.transcribe(message)?;
                self.step = Step::Finished { profile, master };
                Ok(())
            }
            (Step::Finished { profile, master }, HandshakeMessage::Finished(finished)) => {
                let expected = master.verify_data(Role::Client, &core.transcript.hash());
                if !finished.matches(&expected) {
                    return Err(Failure::BadFinished);
                }
                core.transcribe(message)?;
                let verify_data = master.verify_data(Role::Server, &core.transcript.hash());
                let mut body = Vec::new();
                Finished { verify_data }.encode(&mut body);
                let finished = core.message(HandshakeType::FINISHED, body)?;
                // flight 6 is the last: no timer, and sent again only when
                // the client sends flight 5 again
                core.send_flight(vec![super::Item::ChangeCipherSpec, finished], false, now)?;
                core.complete(&master, profile)
            }
            _ => Err(Failure::UnexpectedMessage),
        }
    }
}

/// The ServerHello's extensions.
fn answered(answer: &Answer) -> Result<Extensions, Error> {
    let mut extensions = Extensions::new();
    if answer.secure_renegotiation {
        extensions.push(Extension::RenegotiationInfo(Vec::new()))?;
    }
    extensions.push(Extension::ExtendedMasterSecret)?;
    // RFC 5764 §4.1.3: an MKI the client offered is answered with an empty one
    extensions.push(Extension::UseSrtp(UseSrtp {
        profiles: vec![answer.profile],
        mki: Vec::new(),
    }))?;
    if answer.point_formats {
        extensions.push(Extension::EcPointFormats(vec![EcPointFormat::UNCOMPRESSED]))?;
    }
    Ok(extensions)
}
