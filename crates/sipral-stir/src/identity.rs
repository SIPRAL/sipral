// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The Identity header field of RFC 8224 §4.1, read and written.
//!
//! ```text
//! Identity = "Identity" HCOLON signed-identity-digest SEMI
//!            ident-info *( SEMI ident-info-params )
//! signed-identity-digest = 1*(base64-char / ".")
//! ident-info = "info" EQUAL ident-info-uri
//! ident-info-uri = LAQUOT absoluteURI RAQUOT
//! ident-info-params = ident-info-alg / ident-type / ident-info-extension
//! ident-info-alg = "alg" EQUAL token
//! ident-type = "ppt" EQUAL token
//! ident-info-extension = generic-param
//! ```
//!
//! What is read here is the field value, after `Identity:` and with any line
//! folding already undone. The digest is a PASSporT in the JWS compact
//! serialisation, either in full (`header.claims.signature`) or in the
//! compact form of RFC 8225 §7, where header and claims are left out
//! (`..signature`) and the verifier rebuilds them from the request.
//!
//! `ppt` is also accepted as a quoted string, which deployments send, and
//! is always written as a token. Parameters this crate does not know are
//! skipped, as `ident-info-extension` allows.

use std::fmt;

use crate::MAX_IDENTITY_LEN;
use crate::verdict::{Failure, InfoProblem, Malformed};

/// The PASSporT an Identity header field carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// All three segments, base64url as they arrived.
    Full {
        /// The protected header.
        header: String,
        /// The claims.
        claims: String,
        /// The signature.
        signature: String,
    },
    /// The compact form: the signature alone.
    Compact {
        /// The signature, base64url.
        signature: String,
    },
}

/// An Identity header field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The PASSporT.
    pub token: Token,
    /// The `info` parameter: the URI of the signer's certificate, without
    /// its angle brackets.
    pub info: String,
    /// The `alg` parameter.
    pub alg: Option<String>,
    /// The `ppt` parameter, unquoted.
    pub ppt: Option<String>,
}

impl Identity {
    /// Read a header field value.
    ///
    /// # Errors
    ///
    /// [`Failure::Malformed`] for a value longer than
    /// [`MAX_IDENTITY_LEN`], one that does not follow the grammar, or one
    /// that repeats a parameter; [`Failure::BadInfo`] when `info` is missing
    /// or is not an absolute URI.
    pub fn parse(value: &str) -> Result<Self, Failure> {
        if value.len() > MAX_IDENTITY_LEN {
            return Err(Failure::Malformed(Malformed::TooLong));
        }
        let syntax = Failure::Malformed(Malformed::Syntax);
        let mut rest = value.trim_matches(is_lws);
        let digest_end = rest
            .find(|c: char| c == ';' || is_lws(c))
            .unwrap_or(rest.len());
        let (digest, tail) = rest.split_at(digest_end);
        rest = tail;
        let token = parse_digest(digest).ok_or(syntax)?;

        let mut info = None;
        let mut alg = None;
        let mut ppt = None;
        let mut seen: Vec<String> = Vec::new();
        loop {
            rest = rest.trim_start_matches(is_lws);
            if rest.is_empty() {
                break;
            }
            rest = rest.strip_prefix(';').ok_or(syntax)?;
            rest = rest.trim_start_matches(is_lws);
            let name_end = rest.find(|c: char| !is_token_char(c)).unwrap_or(rest.len());
            let (name, tail) = rest.split_at(name_end);
            if name.is_empty() {
                return Err(syntax);
            }
            let name = name.to_ascii_lowercase();
            if seen.contains(&name) {
                return Err(Failure::Malformed(Malformed::DuplicateParameter));
            }
            rest = tail.trim_start_matches(is_lws);
            let value = if let Some(tail) = rest.strip_prefix('=') {
                rest = tail.trim_start_matches(is_lws);
                let (value, tail) = if name == "info" {
                    angle_uri(rest).ok_or(Failure::BadInfo(InfoProblem::InvalidUri))?
                } else {
                    param_value(rest).ok_or(syntax)?
                };
                rest = tail;
                Some(value)
            } else {
                None
            };
            match name.as_str() {
                "info" => info = value,
                "alg" => alg = Some(value.ok_or(syntax)?),
                "ppt" => ppt = Some(value.ok_or(syntax)?),
                _ => {}
            }
            seen.push(name);
        }
        let info = info.ok_or(Failure::BadInfo(InfoProblem::Missing))?;
        if !is_absolute_uri(&info) {
            return Err(Failure::BadInfo(InfoProblem::InvalidUri));
        }
        Ok(Identity {
            token,
            info,
            alg,
            ppt,
        })
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.token {
            Token::Full {
                header,
                claims,
                signature,
            } => write!(f, "{header}.{claims}.{signature}")?,
            Token::Compact { signature } => write!(f, "..{signature}")?,
        }
        write!(f, ";info=<{}>", self.info)?;
        if let Some(alg) = &self.alg {
            write!(f, ";alg={alg}")?;
        }
        if let Some(ppt) = &self.ppt {
            write!(f, ";ppt={ppt}")?;
        }
        Ok(())
    }
}

fn is_lws(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// RFC 3261 §25.1 `token`.
fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "-.!%*_+`'~".contains(c)
}

fn is_base64url(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'-' || c == b'_'
}

fn parse_digest(digest: &str) -> Option<Token> {
    if !digest.bytes().all(|b| is_base64url(b) || b == b'.') {
        return None;
    }
    let mut segments = digest.split('.');
    let header = segments.next()?;
    let claims = segments.next()?;
    let signature = segments.next()?;
    if segments.next().is_some() || signature.is_empty() {
        return None;
    }
    match (header.is_empty(), claims.is_empty()) {
        (true, true) => Some(Token::Compact {
            signature: signature.to_owned(),
        }),
        (false, false) => Some(Token::Full {
            header: header.to_owned(),
            claims: claims.to_owned(),
            signature: signature.to_owned(),
        }),
        _ => None,
    }
}

/// `<absoluteURI>`, and what follows it.
fn angle_uri(input: &str) -> Option<(String, &str)> {
    let inner = input.strip_prefix('<')?;
    let end = inner.find('>')?;
    let (uri, tail) = inner.split_at(end);
    Some((uri.to_owned(), tail.get(1..)?))
}

/// A token or a quoted string (RFC 3261 §25.1), unquoted, and what follows.
fn param_value(input: &str) -> Option<(String, &str)> {
    if let Some(inner) = input.strip_prefix('"') {
        let mut value = String::new();
        let mut chars = inner.char_indices();
        while let Some((i, c)) = chars.next() {
            match c {
                '"' => return Some((value, inner.get(i + 1..)?)),
                '\\' => {
                    let (_, escaped) = chars.next()?;
                    if escaped.is_ascii_control() && escaped != '\t' {
                        return None;
                    }
                    value.push(escaped);
                }
                c if c.is_ascii_control() && c != '\t' => return None,
                c => value.push(c),
            }
        }
        None
    } else {
        let end = input
            .find(|c: char| !is_token_char(c))
            .unwrap_or(input.len());
        if end == 0 {
            return None;
        }
        let (value, tail) = input.split_at(end);
        Some((value.to_owned(), tail))
    }
}

/// Whether `uri` is an absolute URI (RFC 3986 §4.3): a scheme, a colon, and
/// something after it, all of it visible ASCII outside the delimiters that
/// cannot appear in one unescaped.
pub(crate) fn is_absolute_uri(uri: &str) -> bool {
    let Some((scheme, rest)) = uri.split_once(':') else {
        return false;
    };
    let mut scheme_chars = scheme.chars();
    scheme_chars.next().is_some_and(|c| c.is_ascii_alphabetic())
        && scheme_chars.all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
        && !rest.is_empty()
        && uri
            .bytes()
            .all(|b| b.is_ascii_graphic() && !b"<>\"{}|\\^`".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHAKEN: &str = "eyJhbGciOiJFUzI1NiJ9.eyJpYXQiOjF9.c2ln;info=<https://cert.example.org/passport.cer>;alg=ES256;ppt=shaken";

    fn full() -> Token {
        Token::Full {
            header: "eyJhbGciOiJFUzI1NiJ9".to_owned(),
            claims: "eyJpYXQiOjF9".to_owned(),
            signature: "c2ln".to_owned(),
        }
    }

    #[test]
    fn full_form_with_all_parameters() {
        let identity = Identity::parse(SHAKEN).unwrap();
        assert_eq!(
            identity,
            Identity {
                token: full(),
                info: "https://cert.example.org/passport.cer".to_owned(),
                alg: Some("ES256".to_owned()),
                ppt: Some("shaken".to_owned()),
            }
        );
        assert_eq!(identity.to_string(), SHAKEN);
    }

    #[test]
    fn compact_form() {
        let value = "..c2ln;info=<https://cert.example.org/passport.cer>;alg=ES256";
        let identity = Identity::parse(value).unwrap();
        assert_eq!(
            identity.token,
            Token::Compact {
                signature: "c2ln".to_owned()
            }
        );
        assert_eq!(identity.ppt, None);
        assert_eq!(identity.to_string(), value);
    }

    #[test]
    fn whitespace_case_and_quoting() {
        let identity = Identity::parse(
            " eyJhbGciOiJFUzI1NiJ9.eyJpYXQiOjF9.c2ln ;\tINFO = <https://a.example/c> ; Ppt=\"shaken\" ;x-ext; y=1 ",
        )
        .unwrap();
        assert_eq!(identity.token, full());
        assert_eq!(identity.info, "https://a.example/c");
        assert_eq!(identity.ppt.as_deref(), Some("shaken"));
        assert_eq!(identity.alg, None);
        let escaped = Identity::parse("a.b.c;info=<https://a.example/c>;ppt=\"sha\\ken\"").unwrap();
        assert_eq!(escaped.ppt.as_deref(), Some("shaken"));
    }

    #[test]
    fn info_is_required_and_must_be_an_absolute_uri() {
        assert_eq!(
            Identity::parse("a.b.c;alg=ES256"),
            Err(Failure::BadInfo(InfoProblem::Missing))
        );
        assert_eq!(
            Identity::parse("a.b.c;info"),
            Err(Failure::BadInfo(InfoProblem::Missing))
        );
        for bad in [
            "a.b.c;info=https://a.example/c",
            "a.b.c;info=<https://a.example/c",
            "a.b.c;info=<cert.pem>",
            "a.b.c;info=<https:>",
            "a.b.c;info=<1https://a.example/c>",
            "a.b.c;info=<https://a.example/ c>",
            "a.b.c;info=<https://a.example/\"c>",
            "a.b.c;info=<>",
        ] {
            assert_eq!(
                Identity::parse(bad),
                Err(Failure::BadInfo(InfoProblem::InvalidUri)),
                "{bad}"
            );
        }
    }

    #[test]
    fn digest_syntax() {
        let syntax = Err(Failure::Malformed(Malformed::Syntax));
        for bad in [
            ";info=<https://a.example/c>",
            "a.b;info=<https://a.example/c>",
            "a.b.c.d;info=<https://a.example/c>",
            "a.b.;info=<https://a.example/c>",
            "a..c;info=<https://a.example/c>",
            ".b.c;info=<https://a.example/c>",
            "...;info=<https://a.example/c>",
            "a+b.c.d;info=<https://a.example/c>",
            "a.b/c.d;info=<https://a.example/c>",
            "a.b.c=;info=<https://a.example/c>",
        ] {
            assert_eq!(Identity::parse(bad), syntax, "{bad}");
        }
    }

    #[test]
    fn parameter_syntax() {
        let syntax = Err(Failure::Malformed(Malformed::Syntax));
        for bad in [
            "a.b.c info=<https://a.example/c>",
            "a.b.c;;info=<https://a.example/c>",
            "a.b.c;info=<https://a.example/c>;",
            "a.b.c;info=<https://a.example/c>;alg",
            "a.b.c;info=<https://a.example/c>;ppt",
            "a.b.c;info=<https://a.example/c>;alg=",
            "a.b.c;info=<https://a.example/c>;ppt=\"shaken",
            "a.b.c;info=<https://a.example/c>;ppt=\"sha\u{1}ken\"",
            "a.b.c;info=<https://a.example/c>;ppt=shaken x",
            "a.b.c;info=<https://a.example/c>x",
        ] {
            assert_eq!(Identity::parse(bad), syntax, "{bad}");
        }
    }

    #[test]
    fn repeated_parameters_are_refused() {
        let duplicate = Err(Failure::Malformed(Malformed::DuplicateParameter));
        assert_eq!(
            Identity::parse("a.b.c;info=<https://a.example/c>;info=<https://b.example/c>"),
            duplicate
        );
        assert_eq!(
            Identity::parse("a.b.c;info=<https://a.example/c>;ppt=shaken;PPT=div"),
            duplicate
        );
    }

    #[test]
    fn the_length_is_bounded() {
        let suffix = ".b.c;info=<https://a.example/c>";
        let fits = format!("{}{suffix}", "A".repeat(MAX_IDENTITY_LEN - suffix.len()));
        assert_eq!(fits.len(), MAX_IDENTITY_LEN);
        assert!(Identity::parse(&fits).is_ok());
        let long = format!("A{fits}");
        assert_eq!(
            Identity::parse(&long),
            Err(Failure::Malformed(Malformed::TooLong))
        );
    }
}
