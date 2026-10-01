// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The client's side: flights 1, 3 and 5 of RFC 6347 §4.2.4, and what it
//! checks in the server's.

use std::mem;
use std::time::Instant;

use super::{CLIENT_SUITES, Core, Failure};
use crate::handshake::{
    COMPRESSION_NULL, Certificate as CertificateMessage, CertificateRequest, CertificateVerify,
    CipherSuite, ClientHello, ClientKeyExchange, DigitallySigned, EcPointFormat, Extension,
    ExtensionType, Extensions, Finished, HandshakeMessage, HandshakeType, HelloVerifyRequest,
    Message, NamedGroup, ServerHello, ServerKeyExchange, SignatureAndHash, SrtpProtectionProfile,
    Transcript, UseSrtp,
};
use crate::keys::{CertifiedKey, EphemeralKey};
use crate::prf::{MasterSecret, RANDOM_LEN, VERIFY_DATA_LEN};
use crate::record::ProtocolVersion;
use crate::{Error, Random, Role};

/// How many HelloVerifyRequests one handshake answers. §4.2.1 expects more
/// than one when a server changes its secret; a server that keeps sending
/// them is not going to let the handshake proceed.
const HELLO_VERIFY_REQUESTS: u8 = 4;

/// The extensions a ServerHello may carry: those the ClientHello offered
/// that a server echoes. `supported_groups` and `signature_algorithms` are
/// the client's to send and never a server's.
const ANSWERABLE: [ExtensionType; 4] = [
    ExtensionType::EC_POINT_FORMATS,
    ExtensionType::USE_SRTP,
    ExtensionType::EXTENDED_MASTER_SECRET,
    ExtensionType::RENEGOTIATION_INFO,
];

/// What the ServerHello settled.
struct Chosen {
    server_random: [u8; RANDOM_LEN],
    profile: SrtpProtectionProfile,
    suite: CipherSuite,
}

/// The message the client is waiting for, with what it has learned so far.
enum Step {
    ServerHello,
    Certificate(Chosen),
    ServerKeyExchange(Chosen, CertifiedKey),
    CertificateRequest(Chosen, Vec<u8>),
    ServerHelloDone(Chosen, Vec<u8>),
    Finished {
        profile: SrtpProtectionProfile,
        master: MasterSecret,
        expected: [u8; VERIFY_DATA_LEN],
    },
    Done,
}

pub(super) struct Client {
    random: [u8; RANDOM_LEN],
    ephemeral: Option<EphemeralKey>,
    hello: ClientHello,
    hello_verify_requests: u8,
    step: Step,
}

impl Client {
    pub(super) fn new<R: Random + ?Sized>(
        random: &mut R,
        profiles: &[SrtpProtectionProfile],
    ) -> Result<Self, Error> {
        let mut client_random = [0u8; RANDOM_LEN];
        random.fill(&mut client_random);
        let ephemeral = EphemeralKey::generate(random)?;
        let hello = ClientHello {
            client_version: ProtocolVersion::DTLS_1_2,
            random: client_random,
            session_id: Vec::new(),
            cookie: Vec::new(),
            cipher_suites: CLIENT_SUITES.to_vec(),
            compression_methods: vec![COMPRESSION_NULL],
            extensions: Some(offered(profiles)?),
        };
        Ok(Self {
            random: client_random,
            ephemeral: Some(ephemeral),
            hello,
            hello_verify_requests: 0,
            step: Step::ServerHello,
        })
    }

    /// Whether flight 5 is out and the server's Finished is all that is left.
    pub(super) const fn awaits_finished(&self) -> bool {
        matches!(self.step, Step::Finished { .. })
    }

    /// Flight 1.
    pub(super) fn start(&mut self, core: &mut Core, now: Instant) -> Result<(), Failure> {
        self.send_hello(core, now)
    }

    /// A ClientHello, the first or one answering a HelloVerifyRequest: the
    /// transcript starts again with it, since neither an earlier ClientHello
    /// nor a HelloVerifyRequest is part of it (RFC 6347 §4.2.6).
    fn send_hello(&mut self, core: &mut Core, now: Instant) -> Result<(), Failure> {
        let mut body = Vec::new();
        self.hello.encode(&mut body).map_err(Failure::Internal)?;
        core.transcript = Transcript::new();
        let hello = core.message(HandshakeType::CLIENT_HELLO, body)?;
        core.send_flight(vec![hello], true, now)
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
            (Step::ServerHello, HandshakeMessage::HelloVerifyRequest(request)) => {
                self.hello_verify_request(core, request, now)
            }
            (Step::ServerHello, HandshakeMessage::ServerHello(hello)) => {
                let chosen = Self::server_hello(core, &hello)?;
                core.transcribe(message)?;
                self.step = Step::Certificate(chosen);
                Ok(())
            }
            (Step::Certificate(chosen), HandshakeMessage::Certificate(certificate)) => {
                let peer = core.peer_key(&certificate)?;
                // RFC 8422 §2.1 and §2.2: the suite the server chose says
                // which kind of key its certificate "MUST contain"
                let fits = match peer {
                    CertifiedKey::P256(_) => {
                        chosen.suite == CipherSuite::ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    }
                    CertifiedKey::Rsa(_) => {
                        chosen.suite == CipherSuite::ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    }
                };
                if !fits {
                    return Err(Failure::UnusableCertificate);
                }
                core.transcribe(message)?;
                self.step = Step::ServerKeyExchange(chosen, peer);
                Ok(())
            }
            (
                Step::ServerKeyExchange(chosen, peer),
                HandshakeMessage::ServerKeyExchange(exchange),
            ) => {
                self.server_key_exchange(&chosen, &peer, &exchange)?;
                core.transcribe(message)?;
                self.step = Step::CertificateRequest(chosen, exchange.public);
                Ok(())
            }
            (
                Step::CertificateRequest(chosen, point),
                HandshakeMessage::CertificateRequest(request),
            ) => {
                if !request
                    .certificate_types
                    .contains(&CertificateRequest::ECDSA_SIGN)
                    || !request
                        .supported_signature_algorithms
                        .contains(&SignatureAndHash::ECDSA_SHA256)
                {
                    return Err(Failure::NoCommonParameters);
                }
                core.transcribe(message)?;
                self.step = Step::ServerHelloDone(chosen, point);
                Ok(())
            }
            // a server that does not ask for a certificate cannot check the
            // fingerprint this end's signalling carried
            (Step::CertificateRequest(..), HandshakeMessage::ServerHelloDone) => {
                Err(Failure::NoCertificate)
            }
            (Step::ServerHelloDone(chosen, point), HandshakeMessage::ServerHelloDone) => {
                core.transcribe(message)?;
                self.key_exchange(core, &chosen, &point, now)
            }
            (
                Step::Finished {
                    profile,
                    master,
                    expected,
                },
                HandshakeMessage::Finished(finished),
            ) => {
                if !finished.matches(&expected) {
                    return Err(Failure::BadFinished);
                }
                // the server sends the last flight: nothing of ours is ever
                // sent again
                core.flight = None;
                core.complete(&master, profile)
            }
            _ => Err(Failure::UnexpectedMessage),
        }
    }

    fn hello_verify_request(
        &mut self,
        core: &mut Core,
        request: HelloVerifyRequest,
        now: Instant,
    ) -> Result<(), Failure> {
        // §4.2.1: the version in it is "solely to indicate packet formatting"
        self.hello_verify_requests += 1;
        if self.hello_verify_requests > HELLO_VERIFY_REQUESTS {
            return Err(Failure::UnexpectedMessage);
        }
        self.hello.cookie = request.cookie;
        self.step = Step::ServerHello;
        self.send_hello(core, now)
    }

    fn server_hello(core: &Core, hello: &ServerHello) -> Result<Chosen, Failure> {
        if hello.server_version != ProtocolVersion::DTLS_1_2 {
            return Err(Failure::ProtocolVersion);
        }
        if !CLIENT_SUITES.contains(&hello.cipher_suite)
            || hello.compression_method != COMPRESSION_NULL
        {
            return Err(Failure::IllegalParameter);
        }
        let extensions = hello
            .extensions
            .as_ref()
            .ok_or(Failure::NoExtendedMasterSecret)?;
        if extensions
            .iter()
            .any(|extension| !ANSWERABLE.contains(&extension.extension_type()))
        {
            return Err(Failure::UnsupportedExtension);
        }
        if !extensions.extended_master_secret() {
            return Err(Failure::NoExtendedMasterSecret);
        }
        // RFC 5746 §3.4: an initial handshake's must be empty
        if extensions
            .renegotiation_info()
            .is_some_and(|connection| !connection.is_empty())
        {
            return Err(Failure::Renegotiation);
        }
        if extensions
            .ec_point_formats()
            .is_some_and(|formats| !formats.contains(&EcPointFormat::UNCOMPRESSED))
        {
            return Err(Failure::IllegalParameter);
        }
        let use_srtp = extensions.use_srtp().ok_or(Failure::NoSrtpProfile)?;
        // RFC 5764 §4.1.1: "a single SRTPProtectionProfile value that the
        // server has chosen", which it "MUST NOT select" from outside the
        // client's list; §4.1.3: a non-empty MKI other than the one offered —
        // and none was — aborts the handshake
        let [profile] = use_srtp.profiles.as_slice() else {
            return Err(Failure::IllegalParameter);
        };
        if !core.settings.srtp_profiles.contains(profile) || !use_srtp.mki.is_empty() {
            return Err(Failure::IllegalParameter);
        }
        Ok(Chosen {
            server_random: hello.random,
            profile: *profile,
            suite: hello.cipher_suite,
        })
    }

    fn server_key_exchange(
        &self,
        chosen: &Chosen,
        peer: &CertifiedKey,
        exchange: &ServerKeyExchange,
    ) -> Result<(), Failure> {
        // RFC 5246 §7.4.1.4.1: a pair this end offered, which for each kind
        // of key is exactly one
        if exchange.named_curve != NamedGroup::SECP256R1
            || exchange.signed_params.algorithm != peer.algorithm()
        {
            return Err(Failure::IllegalParameter);
        }
        let content = exchange
            .signed_content(&self.random, &chosen.server_random)
            .map_err(Failure::Malformed)?;
        peer.verify(
            exchange.signed_params.algorithm,
            &content,
            &exchange.signed_params.signature,
        )
        .map_err(|_| Failure::BadSignature)
    }

    /// Flight 5: Certificate, ClientKeyExchange, CertificateVerify,
    /// ChangeCipherSpec, Finished.
    fn key_exchange(
        &mut self,
        core: &mut Core,
        chosen: &Chosen,
        point: &[u8],
        now: Instant,
    ) -> Result<(), Failure> {
        let ephemeral = self
            .ephemeral
            .take()
            .ok_or(Failure::Internal(Error::IllegalValue))?;
        let public = ephemeral.public_key();
        let pre_master = ephemeral
            .agree(point)
            .map_err(|_| Failure::IllegalParameter)?;

        let mut flight = Vec::with_capacity(5);
        let mut body = Vec::new();
        CertificateMessage {
            certificate_list: vec![core.settings.certificate.clone()],
        }
        .encode(&mut body)
        .map_err(Failure::Internal)?;
        flight.push(core.message(HandshakeType::CERTIFICATE, body)?);

        let mut body = Vec::new();
        ClientKeyExchange {
            public: public.to_vec(),
        }
        .encode(&mut body)
        .map_err(Failure::Internal)?;
        flight.push(core.message(HandshakeType::CLIENT_KEY_EXCHANGE, body)?);

        // RFC 7627 §3: the session hash runs through ClientKeyExchange, and
        // so does what CertificateVerify signs (RFC 5246 §7.4.8)
        let session_hash = core.transcript.hash();
        let master = MasterSecret::extended(
            pre_master.as_bytes(),
            &session_hash,
            self.random,
            chosen.server_random,
        );
        let signature = core
            .settings
            .key
            .sign_digest(&session_hash)
            .map_err(Failure::Internal)?;
        let mut body = Vec::new();
        CertificateVerify {
            signed: DigitallySigned {
                algorithm: SignatureAndHash::ECDSA_SHA256,
                signature,
            },
        }
        .encode(&mut body)
        .map_err(Failure::Internal)?;
        flight.push(core.message(HandshakeType::CERTIFICATE_VERIFY, body)?);

        flight.push(super::Item::ChangeCipherSpec);
        let verify_data = master.verify_data(Role::Client, &core.transcript.hash());
        let mut body = Vec::new();
        Finished { verify_data }.encode(&mut body);
        flight.push(core.message(HandshakeType::FINISHED, body)?);

        // the server's Finished covers ours
        let expected = master.verify_data(Role::Server, &core.transcript.hash());
        core.install_keys(&master)?;
        self.step = Step::Finished {
            profile: chosen.profile,
            master,
            expected,
        };
        core.send_flight(flight, true, now)
    }
}

/// The extensions of the ClientHello.
fn offered(profiles: &[SrtpProtectionProfile]) -> Result<Extensions, Error> {
    let mut extensions = Extensions::new();
    extensions.push(Extension::SupportedGroups(vec![NamedGroup::SECP256R1]))?;
    extensions.push(Extension::EcPointFormats(vec![EcPointFormat::UNCOMPRESSED]))?;
    extensions.push(Extension::SignatureAlgorithms(vec![
        SignatureAndHash::ECDSA_SHA256,
        SignatureAndHash::RSA_PKCS1_SHA256,
    ]))?;
    extensions.push(Extension::UseSrtp(UseSrtp {
        profiles: profiles.to_vec(),
        mki: Vec::new(),
    }))?;
    extensions.push(Extension::ExtendedMasterSecret)?;
    // RFC 5746 §3.4: the empty extension, rather than the signalling suite
    extensions.push(Extension::RenegotiationInfo(Vec::new()))?;
    Ok(extensions)
}
