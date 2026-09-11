// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Digest access authentication (RFC 3261 §22, RFC 8760).
//!
//! The computation is three hashes. `A1` is the user, the realm and the
//! password; `A2` is the method and the URI; the response is those two with
//! the nonce and the counter in between. What SIP changes about it is small
//! and specific — the URI is a Request-URI and it is quoted, the entity body
//! hashes as the empty string when there is none — and RFC 8760 adds the SHA-2
//! algorithms and makes `qop` normal rather than optional.
//!
//! The two `-sess` variants exist to bind `A1` to one nonce and one client
//! nonce, so a stolen `A1` cannot be replayed against a later challenge. They
//! need a client nonce, which means they need `qop`: §22.4 rule 8 says a
//! cnonce "MUST NOT be sent ... if no qop directive has been sent", so an
//! algorithm that depends on one cannot be used without it.
//!
//! Nothing here draws a client nonce. The core has no randomness, as it has no
//! clock; the caller supplies both.

use core::fmt;
use std::sync::Arc;

use super::md5::md5;
use super::secret::{Credentials, Secret};
use super::sha2::{sha256, sha512_256};
use crate::msg::{ChallengeRef, HeaderName, Method};

/// The hash a challenge asks for (RFC 8760 §2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum DigestAlgorithm {
    /// RFC 3261's own, and still what most registrars challenge with.
    Md5,
    /// MD5 with `A1` bound to the nonce and the client nonce.
    Md5Sess,
    /// RFC 8760.
    Sha256,
    /// RFC 8760, bound to the nonces.
    Sha256Sess,
    /// RFC 8760.
    Sha512_256,
    /// RFC 8760, bound to the nonces.
    Sha512_256Sess,
}

impl DigestAlgorithm {
    /// The name as it is written in the `algorithm` parameter.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
            Self::Sha512_256 => "SHA-512-256",
            Self::Sha512_256Sess => "SHA-512-256-sess",
        }
    }

    /// Read the `algorithm` parameter. The name is a token, and §7.3.1 makes
    /// tokens case-insensitive, whatever case the server chose.
    #[must_use]
    pub fn from_name(name: &[u8]) -> Option<Self> {
        [
            Self::Md5,
            Self::Md5Sess,
            Self::Sha256,
            Self::Sha256Sess,
            Self::Sha512_256,
            Self::Sha512_256Sess,
        ]
        .into_iter()
        .find(|candidate| name.eq_ignore_ascii_case(candidate.name().as_bytes()))
    }

    /// Whether `A1` is bound to the nonces, which also means the algorithm
    /// cannot be used without `qop`.
    #[must_use]
    pub const fn is_session(self) -> bool {
        matches!(
            self,
            Self::Md5Sess | Self::Sha256Sess | Self::Sha512_256Sess
        )
    }

    /// The hex digest, lower case, as §2.2 requires: "represented by its
    /// familiar hexadecimal notation from the characters 0123456789abcdef".
    #[must_use]
    pub fn hash(self, data: &[u8]) -> String {
        match self {
            Self::Md5 | Self::Md5Sess => hex(&md5(data)),
            Self::Sha256 | Self::Sha256Sess => hex(&sha256(data)),
            Self::Sha512_256 | Self::Sha512_256Sess => hex(&sha512_256(data)),
        }
    }
}

impl fmt::Display for DigestAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A challenge we can answer.
///
/// Built from a `WWW-Authenticate` or `Proxy-Authenticate` value that names
/// Digest and an algorithm we have; anything else is not a challenge as far as
/// this stack is concerned, and RFC 8760 §2.4 says so: "The client MUST ignore
/// any challenge it does not understand."
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The protection domain the credentials belong to.
    pub realm: Arc<str>,
    /// The server's nonce, echoed back untouched.
    pub nonce: Arc<str>,
    /// Echoed back if the server sent one.
    pub opaque: Option<Arc<str>>,
    /// The hash to use.
    pub algorithm: DigestAlgorithm,
    /// Whether the server offered `qop=auth`.
    pub qop_auth: bool,
    /// Whether the server said the nonce was merely old, which means the same
    /// credentials are worth sending again against the new one.
    pub stale: bool,
    /// Whether it came from a proxy (407) rather than the endpoint (401).
    /// The two are separate spaces and separate header fields.
    pub proxy: bool,
}

impl Challenge {
    /// Read a challenge, or decide it is not one we can answer.
    #[must_use]
    pub fn read(challenge: &ChallengeRef<'_>, proxy: bool) -> Option<Self> {
        if !challenge.is_digest() {
            return None;
        }
        let algorithm = match challenge.algorithm() {
            // "This document extends RFC 3261 to allow use of any algorithm
            // listed in the registry"; RFC 3261 §22.4 leaves MD5 the default.
            Some(name) => DigestAlgorithm::from_name(&name)?,
            None => DigestAlgorithm::Md5,
        };
        let qop_auth = challenge.qop().any(|q| q.eq_ignore_ascii_case(b"auth"));
        if algorithm.is_session() && !qop_auth {
            // §22.4 rule 8: no qop, no cnonce, and no cnonce means no -sess
            return None;
        }
        Some(Self {
            realm: text(&challenge.realm()?)?,
            nonce: text(&challenge.nonce()?)?,
            opaque: challenge.opaque().as_deref().and_then(text),
            algorithm,
            qop_auth,
            stale: challenge.stale().ok().flatten().unwrap_or(false),
            proxy,
        })
    }

    /// Which header field the answer goes in.
    #[must_use]
    pub const fn header(&self) -> HeaderName<'static> {
        if self.proxy {
            HeaderName::ProxyAuthorization
        } else {
            HeaderName::Authorization
        }
    }

    /// The credentials answering this challenge, ready to be a header value.
    ///
    /// `count` is the number of times this client nonce has been used with
    /// this challenge, starting at one, and `cnonce` is the caller's client
    /// nonce — unused, and omitted from the message, when the server offered
    /// no `qop`.
    #[must_use]
    pub fn respond(
        &self,
        credentials: &Credentials,
        method: Method<'_>,
        uri: &[u8],
        count: u32,
        cnonce: &str,
    ) -> String {
        let algorithm = self.algorithm;
        let nc = format!("{count:08x}");

        // A1 = username:realm:password, and for -sess that hashed again with
        // both nonces, which is what binds it to this exchange. It holds the
        // password, so it lives in the buffer that wipes itself on drop
        // rather than in a `Vec` that leaves the last copy of it in freed
        // memory — and on an unwind as well, which a wipe written at the
        // tail of this function would not give.
        let a1 = Secret::joined(&[
            credentials.username.as_bytes(),
            self.realm.as_bytes(),
            credentials.password(),
        ]);
        // HA1 below is password-equivalent for answering a challenge and is a
        // `String` that is not wiped. That is a scope decision rather than an
        // oversight: wiping it needs `hash` to hand back raw bytes with the
        // hexadecimal done at the edge, which is every caller of `hash`.
        let ha1 = if algorithm.is_session() {
            algorithm.hash(&join(&[
                algorithm.hash(a1.expose()).as_bytes(),
                self.nonce.as_bytes(),
                cnonce.as_bytes(),
            ]))
        } else {
            algorithm.hash(a1.expose())
        };

        // A2 = method:digest-uri. The other form, with the body hashed in, is
        // qop=auth-int, which is not offered here: it needs the body of every
        // request kept around for a retry, and no SIP server in the field
        // asks for it.
        let ha2 = algorithm.hash(&join(&[method.as_str().as_bytes(), uri]));

        let response = if self.qop_auth {
            algorithm.hash(&join(&[
                ha1.as_bytes(),
                self.nonce.as_bytes(),
                nc.as_bytes(),
                cnonce.as_bytes(),
                b"auth",
                ha2.as_bytes(),
            ]))
        } else {
            // the RFC 2069 shape, which SIP keeps for servers that predate qop
            algorithm.hash(&join(&[
                ha1.as_bytes(),
                self.nonce.as_bytes(),
                ha2.as_bytes(),
            ]))
        };

        let mut out = String::from("Digest ");
        quoted(&mut out, "username", credentials.username.as_bytes());
        out.push_str(", ");
        quoted(&mut out, "realm", self.realm.as_bytes());
        out.push_str(", ");
        quoted(&mut out, "nonce", self.nonce.as_bytes());
        out.push_str(", ");
        // "For SIP, the 'uri' MUST be enclosed in quotation marks."
        quoted(&mut out, "uri", uri);
        out.push_str(", ");
        quoted(&mut out, "response", response.as_bytes());
        // the algorithm is a token and goes unquoted; naming it even when it
        // is the default costs nothing and removes a guess
        out.push_str(", algorithm=");
        out.push_str(algorithm.name());
        if self.qop_auth {
            // in credentials qop is a single token, not the quoted list it is
            // in the challenge
            out.push_str(", qop=auth, nc=");
            out.push_str(&nc);
            out.push_str(", ");
            quoted(&mut out, "cnonce", cnonce.as_bytes());
        }
        if let Some(opaque) = &self.opaque {
            out.push_str(", ");
            quoted(&mut out, "opaque", opaque.as_bytes());
        }
        out
    }
}

fn text(bytes: &[u8]) -> Option<Arc<str>> {
    core::str::from_utf8(bytes).ok().map(Arc::from)
}

fn join(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len() + 1).sum());
    for (index, part) in parts.iter().enumerate() {
        if index > 0 {
            out.push(b':');
        }
        out.extend_from_slice(part);
    }
    out
}

pub(crate) fn hex(digest: &[u8]) -> String {
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(char::from(nibble(byte >> 4)));
        out.push(char::from(nibble(byte & 0x0f)));
    }
    out
}

const fn nibble(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'a' + value - 10,
    }
}

/// `name="value"`, with the two characters a quoted string cannot hold raw
/// written as escapes (RFC 3261 §25.1 `quoted-pair`).
fn quoted(out: &mut String, name: &str, value: &[u8]) {
    out.push_str(name);
    out.push_str("=\"");
    for byte in value {
        if matches!(byte, b'"' | b'\\') {
            out.push('\\');
        }
        out.push(char::from(*byte));
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::{Challenge, DigestAlgorithm};
    use crate::auth::Credentials;
    use crate::msg::{ChallengeRef, CredentialsRef, Method};

    fn challenge(value: &str, proxy: bool) -> Challenge {
        let parsed = ChallengeRef::parse(value.as_bytes()).expect("a challenge");
        Challenge::read(&parsed, proxy).expect("one we can answer")
    }

    /// What the far end reads back out of what we wrote, through our own
    /// parser: a value that cannot be read is not an answer.
    fn field(value: &str, name: &str) -> Option<String> {
        let parsed = CredentialsRef::parse(value.as_bytes()).expect("our own credentials");
        assert!(parsed.is_digest());
        parsed
            .param(name)
            .map(|value| String::from_utf8_lossy(&value).into_owned())
    }

    /// The A1 buffer holds the password, so it has to be the type that wipes
    /// itself on drop rather than one that leaves its last copy in freed
    /// memory. A wipe is not observable from safe Rust and Miri cannot be
    /// pointed at this, so what is asserted is the one thing that is visible:
    /// which type the path uses. The needles are assembled at runtime, so the
    /// test cannot pass by matching its own assertion.
    #[test]
    fn the_password_is_never_built_in_a_buffer_that_is_not_wiped() {
        let source = include_str!("digest.rs").replace("\r\n", "\n");
        let opens = "    pub fn respond(";
        let from = source.find(opens).expect("respond is in this file");
        let rest = source.get(from..).expect("the rest of the file");
        let to = rest.find("\n    }\n").map_or(rest.len(), |at| at + 1);
        let body = rest.get(..to).expect("the body of respond");
        assert!(
            body.len() > opens.len(),
            "the slice is the function, not the signature"
        );

        let wiping = format!("{}::{}", "Secret", "joined");
        assert!(
            body.contains(&wiping),
            "A1 holds the password and is built with {wiping}"
        );
        for grown in [
            format!("{}::{}", "Vec", "new"),
            format!("{}::{}", "Vec", "with_capacity"),
            format!("{}{}", "to_", "vec()"),
        ] {
            assert!(
                !body.contains(&grown),
                "the password must not pass through {grown}"
            );
        }
    }

    #[test]
    fn the_worked_example_of_the_http_specification() {
        // The example every digest implementation is checked against: Mufasa,
        // "Circle Of Life", that nonce and that client nonce. The realm alone
        // is moved to a reserved domain - the published one reads as an
        // address, and the check that keeps addresses out of this tree is
        // worth more than the last byte of provenance. With the original realm
        // the response is 6629fae49393a05397450978507c4ef1, which is how the
        // vector is recognised.
        let challenge = challenge(
            "Digest realm=\"testrealm.example.com\", \
qop=\"auth,auth-int\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", \
opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
            false,
        );
        let value = challenge.respond(
            &Credentials::new("Mufasa", "Circle Of Life"),
            Method::from_bytes(b"GET").expect("a method"),
            b"/dir/index.html",
            1,
            "0a4f113b",
        );
        assert_eq!(
            field(&value, "response").as_deref(),
            Some("9af0a23c6a2ee2c252998f4fa7a1b84b")
        );
        assert_eq!(
            field(&value, "opaque").as_deref(),
            Some("5ccc069c403ebaf9f0171e9517f40e41"),
            "echoed back untouched"
        );
    }

    #[test]
    fn the_three_algorithms_rfc_8760_allows() {
        for (name, expected) in [
            ("MD5", "7fd96a22ed1d64a974701dbd8f92a14e"),
            (
                "SHA-256",
                "a55e42ad87e94eb5b9c03f5942cc829f83420868db57acc6f2dfb1f1084ae6cd",
            ),
            (
                "SHA-512-256",
                "ba423c8f9ca4dacdea50a9e561267b5d880eb52942e82ea10ab3f9c14bb9cbcd",
            ),
        ] {
            let challenge = challenge(
                &format!(
                    "Digest realm=\"example.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm={name}"
                ),
                false,
            );
            let value = challenge.respond(
                &Credentials::new("alice", "secret"),
                Method::Register,
                b"sip:example.com",
                1,
                "0a4f113b",
            );
            assert_eq!(
                field(&value, "response").as_deref(),
                Some(expected),
                "{name}"
            );
            assert_eq!(field(&value, "algorithm").as_deref(), Some(name));
            assert_eq!(field(&value, "nc").as_deref(), Some("00000001"));
            assert_eq!(field(&value, "qop").as_deref(), Some("auth"));
        }
    }

    #[test]
    fn a_session_algorithm_binds_the_secret_to_both_nonces() {
        let challenge = challenge(
            "Digest realm=\"example.com\", \
nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=MD5-sess",
            false,
        );
        let value = challenge.respond(
            &Credentials::new("alice", "secret"),
            Method::Register,
            b"sip:example.com",
            1,
            "0a4f113b",
        );
        assert_eq!(
            field(&value, "response").as_deref(),
            Some("f017e479dbee9ec264fe1118766c910d")
        );
    }

    #[test]
    fn a_session_algorithm_without_qop_is_not_answerable() {
        // §22.4 rule 8: no qop, no cnonce, and -sess cannot be computed
        // without one
        for name in ["MD5-sess", "SHA-256-sess", "SHA-512-256-sess"] {
            let value = format!("Digest realm=\"example.com\", nonce=\"abc\", algorithm={name}");
            let parsed = ChallengeRef::parse(value.as_bytes()).expect("a challenge");
            assert!(Challenge::read(&parsed, false).is_none(), "{name}");
        }
    }

    #[test]
    fn a_server_that_offers_no_qop_gets_the_older_shape() {
        let challenge = challenge(
            "Digest realm=\"example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"",
            false,
        );
        assert!(!challenge.qop_auth);
        assert_eq!(challenge.algorithm, DigestAlgorithm::Md5, "the default");

        let value = challenge.respond(
            &Credentials::new("alice", "secret"),
            Method::Register,
            b"sip:example.com",
            1,
            "0a4f113b",
        );
        assert_eq!(
            field(&value, "response").as_deref(),
            Some("b75dc11e0cde1fc2f921ce28378036bb")
        );
        // "a cnonce value MUST NOT be sent ... if no qop directive has been
        // sent"
        assert!(field(&value, "cnonce").is_none());
        assert!(field(&value, "nc").is_none());
        assert!(field(&value, "qop").is_none());
    }

    #[test]
    fn the_uri_is_quoted_and_the_counter_is_eight_hex_digits() {
        let challenge = challenge(
            "Digest realm=\"example.com\", nonce=\"abc\", qop=\"auth\"",
            false,
        );
        let value = challenge.respond(
            &Credentials::new("alice", "secret"),
            Method::Register,
            b"sip:example.com",
            0x2a,
            "0a4f113b",
        );
        // "For SIP, the 'uri' MUST be enclosed in quotation marks."
        assert!(value.contains("uri=\"sip:example.com\""), "{value}");
        assert!(value.contains("nc=0000002a"), "{value}");
        assert!(value.contains("algorithm=MD5"), "unquoted token");
        assert!(
            value.contains("qop=auth"),
            "a token here, a list in the challenge"
        );
    }

    #[test]
    fn a_quotation_mark_in_a_user_name_cannot_end_the_value() {
        let challenge = challenge("Digest realm=\"example.com\", nonce=\"abc\"", false);
        let value = challenge.respond(
            &Credentials::new("ali\"ce", "secret"),
            Method::Register,
            b"sip:example.com",
            1,
            "0a4f113b",
        );
        assert!(value.contains("username=\"ali\\\"ce\""), "{value}");
        assert_eq!(field(&value, "username").as_deref(), Some("ali\"ce"));
    }

    #[test]
    fn a_challenge_we_cannot_answer_is_not_one() {
        for value in [
            "Basic realm=\"example.com\"",
            "Digest realm=\"example.com\", nonce=\"abc\", algorithm=SHA3-512",
            "Digest nonce=\"abc\"",
            "Digest realm=\"example.com\"",
        ] {
            let parsed = ChallengeRef::parse(value.as_bytes()).expect("a challenge");
            assert!(Challenge::read(&parsed, false).is_none(), "{value}");
        }
    }

    #[test]
    fn a_proxy_challenge_is_answered_in_the_other_field() {
        let www = challenge("Digest realm=\"example.com\", nonce=\"abc\"", false);
        let proxy = challenge("Digest realm=\"example.com\", nonce=\"abc\"", true);
        assert_eq!(www.header().canonical(), "Authorization");
        assert_eq!(proxy.header().canonical(), "Proxy-Authorization");
    }
}
