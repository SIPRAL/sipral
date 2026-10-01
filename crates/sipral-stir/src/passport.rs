// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The PASSporT of RFC 8225 with the `shaken` extension of RFC 8588: its
//! header, its claims, and both in the deterministic JSON form of RFC 8225 §9
//! in which they are signed.
//!
//! Only telephone-number originators are modelled. RFC 8225 §5.2.1 also
//! allows `orig` to be a URI, but the authority this crate checks is a
//! certificate's TNAuthList (RFC 8226 §9), which speaks of numbers and of
//! nothing else, so a PASSporT whose `orig` has no `tn` is refused as
//! malformed rather than accepted with nothing to check it against.

use std::fmt::{self, Write as _};

use crate::json::Value;
use crate::verdict::{Failure, Malformed};

/// The `typ` of every PASSporT (RFC 8225 §4.1).
pub const TYP: &str = "passport";
/// The one signature algorithm this crate signs and verifies with: ECDSA
/// over P-256 with SHA-256 (RFC 7518 §3.4), mandatory to support per RFC
/// 8225 §4.2.
pub const ALG: &str = "ES256";
/// The `ppt` of the SHAKEN extension (RFC 8588 §3).
pub const PPT_SHAKEN: &str = "shaken";

/// The longest telephone number TNAuthList can hold (RFC 8226 §9), and so
/// the longest one this crate can check authority over.
pub const MAX_TN_LEN: usize = 15;

/// A telephone number in the canonical form of RFC 8224 §8.3: no leading
/// `+`, no visual separators, only digits and the `*` and `#` RFC 8226 §9
/// admits, one to fifteen of them.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Tn(String);

/// A string that is not a canonical telephone number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidTn;

impl fmt::Display for InvalidTn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a canonical telephone number")
    }
}

impl std::error::Error for InvalidTn {}

impl Tn {
    /// A number already in canonical form, such as `12155551212`.
    ///
    /// # Errors
    ///
    /// [`InvalidTn`] for an empty string, one longer than
    /// [`MAX_TN_LEN`], or one holding anything but digits, `*` and `#`.
    pub fn new(number: &str) -> Result<Self, InvalidTn> {
        if is_tn(number) {
            Ok(Tn(number.to_owned()))
        } else {
            Err(InvalidTn)
        }
    }

    /// The number in `written` in the canonical form of RFC 8224 §8.3: a
    /// leading `+` and the visual separators of RFC 3966 §5.1.1 (`-`, `.`,
    /// `(`, `)`) and spaces dropped, what is left being one to fifteen of
    /// `0123456789#*` with at least one digit among them.
    ///
    /// Only the first step of §8.3. Turning a national or dial-string
    /// number into E.164 needs the country and dialling plan of the
    /// deployment, which this crate does not know; a number that reaches
    /// here in another form is canonical in that form, as §8.3 allows "in
    /// the case that an implementation cannot determine how to convert the
    /// number". [`Tn::canonical_with`] takes the deployment's plan.
    ///
    /// # Errors
    ///
    /// [`InvalidTn`] for text holding anything else — a letter makes it a
    /// name rather than a number (RFC 8224 §8.1) — or nothing but
    /// separators.
    pub fn canonical(written: &str) -> Result<Self, InvalidTn> {
        Self::canonical_with(written, |_| None)
    }

    /// As [`Tn::canonical`], with the rest of §8.3 left to the deployment:
    /// a number written without a leading `+` is handed to `plan`, its
    /// separators already gone, and what `plan` gives back is the number in
    /// international form — `2155551212` dialled in the United States as
    /// `12155551212`, say. `None` from `plan` keeps the number as written,
    /// which §8.3 allows when it "cannot determine how to convert the
    /// number". A number written with `+` is international already, and
    /// `plan` is not asked.
    ///
    /// Signer and verifier have to convert alike, or a number one signs is
    /// not the number the other checks; that is why the plan is the
    /// deployment's to give and not this crate's to guess.
    ///
    /// # Errors
    ///
    /// As [`Tn::canonical`], and [`InvalidTn`] when what `plan` gives back
    /// is not a canonical number with or without its separators.
    pub fn canonical_with(
        written: &str,
        plan: impl FnOnce(&str) -> Option<String>,
    ) -> Result<Self, InvalidTn> {
        let (international, body) = match written.strip_prefix('+') {
            Some(body) => (true, body),
            None => (false, written),
        };
        let mut number = String::with_capacity(body.len());
        for c in body.chars() {
            match c {
                '0'..='9' | '#' | '*' => number.push(c),
                '-' | '.' | '(' | ')' | ' ' => {}
                _ => return Err(InvalidTn),
            }
        }
        if !number.bytes().any(|b| b.is_ascii_digit()) {
            return Err(InvalidTn);
        }
        if !international && let Some(converted) = plan(&number) {
            return Self::canonical(&converted);
        }
        Tn::new(&number)
    }

    /// The number.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Tn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Whether `number` is one to fifteen of `0123456789#*`: the
/// `TelephoneNumber` of RFC 8226 §9.
pub(crate) fn is_tn(number: &str) -> bool {
    (1..=MAX_TN_LEN).contains(&number.len())
        && number
            .bytes()
            .all(|b| b.is_ascii_digit() || b == b'#' || b == b'*')
}

/// The attestation level of RFC 8588 §4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attest {
    /// Full attestation: the signer knows the caller and that the caller may
    /// use the number.
    A,
    /// Partial attestation: the signer knows the caller, not whether the
    /// caller may use the number.
    B,
    /// Gateway attestation: the signer only knows where the call entered its
    /// network.
    C,
}

impl Attest {
    /// The claim value.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Attest::A => "A",
            Attest::B => "B",
            Attest::C => "C",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "A" => Some(Attest::A),
            "B" => Some(Attest::B),
            "C" => Some(Attest::C),
            _ => None,
        }
    }
}

impl fmt::Display for Attest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The origination identifier of RFC 8588 §5: a UUID (RFC 4122), written in
/// its canonical lower-case form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OrigId([u8; 16]);

/// A string that is not a UUID in the textual form of RFC 4122 §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidOrigId;

impl fmt::Display for InvalidOrigId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a UUID")
    }
}

impl std::error::Error for InvalidOrigId {}

impl OrigId {
    /// The identifier whose sixteen octets are `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        OrigId(bytes)
    }

    /// Read the textual form of RFC 4122 §3, `8-4-4-4-12` hexadecimal digits
    /// in either case.
    ///
    /// # Errors
    ///
    /// [`InvalidOrigId`] for anything else.
    pub fn parse(text: &str) -> Result<Self, InvalidOrigId> {
        let text = text.as_bytes();
        if text.len() != 36 {
            return Err(InvalidOrigId);
        }
        let mut bytes = [0u8; 16];
        let mut nibbles = 0usize;
        for (i, &c) in text.iter().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if c != b'-' {
                    return Err(InvalidOrigId);
                }
                continue;
            }
            let digit = char::from(c).to_digit(16).ok_or(InvalidOrigId)?;
            let digit = u8::try_from(digit).map_err(|_| InvalidOrigId)?;
            let byte = bytes.get_mut(nibbles / 2).ok_or(InvalidOrigId)?;
            *byte = (*byte << 4) | digit;
            nibbles += 1;
        }
        Ok(OrigId(bytes))
    }

    /// The sixteen octets.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for OrigId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, byte) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// The destinations of RFC 8225 §5.2.1: telephone numbers, URIs, or both,
/// at least one in all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Dest {
    /// Called numbers, canonical as [`Tn`] is.
    pub tn: Vec<Tn>,
    /// Called URIs.
    pub uri: Vec<String>,
}

impl Dest {
    /// A single called number.
    #[must_use]
    pub fn tn(number: Tn) -> Self {
        Dest {
            tn: vec![number],
            uri: Vec::new(),
        }
    }

    /// A single called URI, in the canonical form of RFC 8224 §8.5
    /// ([`canonical_uri`]).
    #[must_use]
    pub fn uri(uri: &str) -> Self {
        Dest {
            tn: Vec::new(),
            uri: vec![canonical_uri(uri)],
        }
    }

    /// Whether there is no destination at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.tn.is_empty() && self.uri.is_empty()
    }

    /// Whether `number` is one of the called numbers.
    #[must_use]
    pub fn names_number(&self, number: &Tn) -> bool {
        self.tn.contains(number)
    }

    /// Whether `uri` is one of the called URIs, both sides compared in the
    /// canonical form of RFC 8224 §8.5: a signer that wrote a SIP URI with
    /// its port, parameters or another case still names the same address
    /// of record.
    #[must_use]
    pub fn names_uri(&self, uri: &str) -> bool {
        let wanted = canonical_uri(uri);
        self.uri
            .iter()
            .any(|signed| canonical_uri(signed) == wanted)
    }
}

/// A URI in the canonical form RFC 8224 §8.5 gives a `sip:` or `sips:` URI
/// before it goes into a PASSporT claim such as `dest.uri`:
/// `scheme ":" user "@" host`, with the password, the port, the URI
/// parameters and the headers dropped, scheme, user and host in lower case,
/// and every percent-encoded unreserved character (RFC 3986 §2.3) decoded;
/// an escape that stays is written with upper-case digits (RFC 3986
/// §6.2.2.1). A SIP URI without a user part keeps just its host.
///
/// Any other URI comes back as written, but for its scheme in lower case:
/// §8.5 describes the SIP and SIPS schemes alone.
#[must_use]
pub fn canonical_uri(uri: &str) -> String {
    let trimmed = uri.trim();
    let Some((scheme, rest)) = trimmed.split_once(':') else {
        return trimmed.to_owned();
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "sip" && scheme != "sips" {
        return format!("{scheme}:{rest}");
    }
    // the headers go first: a `?` cannot appear unescaped before them
    let rest = rest.split_once('?').map_or(rest, |(before, _)| before);
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((userinfo, hostport)) => {
            // only the user is kept of the userinfo: the password, and the
            // colon before it, go (§8.5)
            let user = userinfo.split_once(':').map_or(userinfo, |(user, _)| user);
            (Some(user), hostport)
        }
        None => (None, rest),
    };
    let hostport = hostport.split_once(';').map_or(hostport, |(host, _)| host);
    let host = if hostport.starts_with('[') {
        // an IPv6 reference keeps its brackets and its colons
        hostport
            .find(']')
            .and_then(|end| hostport.get(..=end))
            .unwrap_or(hostport)
    } else {
        hostport.split_once(':').map_or(hostport, |(host, _)| host)
    };
    let host = normalised(host);
    match user {
        Some(user) => format!("{scheme}:{}@{host}", normalised(user)),
        None => format!("{scheme}:{host}"),
    }
}

/// Lower case, with each escaped unreserved character decoded and every
/// other escape written with upper-case digits (RFC 3986 §6.2.2).
fn normalised(part: &str) -> String {
    let mut out = String::with_capacity(part.len());
    let mut chars = part.chars();
    while let Some(c) = chars.next() {
        let digits = chars.clone().take(2).collect::<String>();
        let escaped = (c == '%'
            && digits.len() == 2
            && digits.chars().all(|digit| digit.is_ascii_hexdigit()))
        .then(|| u8::from_str_radix(&digits, 16).ok())
        .flatten();
        match escaped {
            Some(byte) => {
                chars.nth(1);
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                    out.push(char::from(byte.to_ascii_lowercase()));
                } else {
                    let _ = write!(out, "%{byte:02X}");
                }
            }
            None => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// The two claims RFC 8588 adds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shaken {
    /// The attestation level.
    pub attest: Attest,
    /// The origination identifier.
    pub origid: OrigId,
}

/// A PASSporT's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    /// The originating number, `orig.tn`.
    pub orig: Tn,
    /// The destinations, `dest`.
    pub dest: Dest,
    /// When it was signed, `iat`, in seconds since the Unix epoch.
    pub iat: u64,
    /// `attest` and `origid`, for a PASSporT with the `shaken` extension;
    /// `None` for a plain one.
    pub shaken: Option<Shaken>,
}

impl Claims {
    /// The claims in the deterministic form of RFC 8225 §9, with `attest`
    /// and `origid` included when [`Claims::shaken`] is set, and each
    /// `dest.uri` in the canonical form of RFC 8224 §8.5 ([`canonical_uri`]).
    #[must_use]
    pub fn to_json(&self) -> String {
        self.value(self.shaken.is_some()).canonical()
    }

    /// The claims as a JSON object, the SHAKEN pair only when `shaken`.
    ///
    /// RFC 8225 §5.2.1: "Within the "tn" and "uri" arrays, the identity
    /// strings should be put in lexicographical order", which is also what
    /// lets a verifier rebuild a compact form's claims from a request that
    /// lists its destinations in another order.
    pub(crate) fn value(&self, shaken: bool) -> Value {
        let mut dest = Vec::new();
        if !self.dest.tn.is_empty() {
            let mut numbers: Vec<&str> = self.dest.tn.iter().map(|tn| tn.0.as_str()).collect();
            numbers.sort_unstable();
            let numbers = numbers
                .into_iter()
                .map(|tn| Value::String(tn.to_owned()))
                .collect();
            dest.push(("tn".to_owned(), Value::Array(numbers)));
        }
        if !self.dest.uri.is_empty() {
            // RFC 8224 §8.5: a SIP URI goes into a claim in its canonical
            // form, which is also the form a verifier rebuilds a compact
            // form's claims in
            let mut uris: Vec<String> =
                self.dest.uri.iter().map(|uri| canonical_uri(uri)).collect();
            uris.sort_unstable();
            let uris = uris.into_iter().map(Value::String).collect();
            dest.push(("uri".to_owned(), Value::Array(uris)));
        }
        let mut members = vec![
            ("dest".to_owned(), Value::Object(dest)),
            ("iat".to_owned(), Value::Number(self.iat.to_string())),
            (
                "orig".to_owned(),
                Value::Object(vec![("tn".to_owned(), Value::String(self.orig.0.clone()))]),
            ),
        ];
        if let (true, Some(extension)) = (shaken, &self.shaken) {
            members.push((
                "attest".to_owned(),
                Value::String(extension.attest.as_str().to_owned()),
            ));
            members.push((
                "origid".to_owned(),
                Value::String(extension.origid.to_string()),
            ));
        }
        Value::Object(members)
    }

    /// Read the claims object of a received PASSporT; `shaken` when its
    /// header says `ppt: "shaken"`, which makes `attest` and `origid`
    /// required. Claims this crate does not know are ignored: PASSporT is
    /// extensible (RFC 8225 §8), and an extension's claims are its own.
    pub(crate) fn from_json(json: &[u8], shaken: bool) -> Result<Self, Failure> {
        let value = Value::parse(json).map_err(|_| Failure::Malformed(Malformed::Json))?;
        if !matches!(value, Value::Object(_)) {
            return Err(Failure::Malformed(Malformed::Json));
        }
        let claims = || Failure::Malformed(Malformed::Claims);
        let iat = value
            .get("iat")
            .and_then(Value::as_u64)
            .ok_or_else(claims)?;
        let orig = value
            .get("orig")
            .and_then(|orig| orig.get("tn"))
            .and_then(Value::as_str)
            .and_then(|tn| Tn::new(tn).ok())
            .ok_or_else(claims)?;
        let dest = value.get("dest").ok_or_else(claims)?;
        if !matches!(dest, Value::Object(_)) {
            return Err(claims());
        }
        let strings = |name: &str| -> Result<Vec<&str>, Failure> {
            match dest.get(name) {
                None => Ok(Vec::new()),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| item.as_str().ok_or_else(claims))
                    .collect(),
                Some(_) => Err(claims()),
            }
        };
        let dest = Dest {
            tn: strings("tn")?
                .into_iter()
                .map(|tn| Tn::new(tn).map_err(|_| claims()))
                .collect::<Result<_, _>>()?,
            uri: strings("uri")?.into_iter().map(str::to_owned).collect(),
        };
        if dest.is_empty() {
            return Err(claims());
        }
        let shaken = if shaken {
            let attest = value
                .get("attest")
                .and_then(Value::as_str)
                .and_then(Attest::parse)
                .ok_or_else(claims)?;
            let origid = value
                .get("origid")
                .and_then(Value::as_str)
                .and_then(|origid| OrigId::parse(origid).ok())
                .ok_or_else(claims)?;
            Some(Shaken { attest, origid })
        } else {
            None
        };
        Ok(Claims {
            orig,
            dest,
            iat,
            shaken,
        })
    }
}

/// The PASSporT header this crate writes: `alg` ES256, `typ` passport, the
/// certificate's URI in `x5u`, and `ppt: "shaken"` when `shaken`, in the
/// deterministic form of RFC 8225 §9.
#[must_use]
pub fn header_json(x5u: &str, shaken: bool) -> String {
    header_value(x5u, shaken).canonical()
}

pub(crate) fn header_value(x5u: &str, shaken: bool) -> Value {
    let mut members = vec![
        ("alg".to_owned(), Value::String(ALG.to_owned())),
        ("typ".to_owned(), Value::String(TYP.to_owned())),
        ("x5u".to_owned(), Value::String(x5u.to_owned())),
    ];
    if shaken {
        members.push(("ppt".to_owned(), Value::String(PPT_SHAKEN.to_owned())));
    }
    Value::Object(members)
}

/// What a received PASSporT header says that matters here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Header {
    /// `x5u`, when present.
    pub(crate) x5u: Option<String>,
    /// Whether `ppt` is `shaken`.
    pub(crate) shaken: bool,
}

impl Header {
    /// Read a received header object, holding it to RFC 8225 §4 and to what
    /// this crate supports.
    pub(crate) fn from_json(json: &[u8]) -> Result<Self, Failure> {
        let value = Value::parse(json).map_err(|_| Failure::Malformed(Malformed::Json))?;
        if !matches!(value, Value::Object(_)) {
            return Err(Failure::Malformed(Malformed::Json));
        }
        let header = || Failure::Malformed(Malformed::Header);
        if value.get("typ").and_then(Value::as_str) != Some(TYP) {
            return Err(header());
        }
        match value.get("alg").map(Value::as_str) {
            Some(Some(ALG)) => {}
            Some(Some(_)) => return Err(Failure::UnsupportedAlgorithm),
            _ => return Err(header()),
        }
        // RFC 7515 §4.1.11: an extension marked critical that the reader
        // does not understand makes the JWS invalid, and none is understood
        if value.get("crit").is_some() {
            return Err(Failure::Malformed(Malformed::Critical));
        }
        let shaken = match value.get("ppt").map(Value::as_str) {
            None => false,
            Some(Some(PPT_SHAKEN)) => true,
            Some(Some(_)) => return Err(Failure::UnsupportedPpt),
            Some(None) => return Err(header()),
        };
        let x5u = match value.get("x5u").map(Value::as_str) {
            None => None,
            Some(Some(x5u)) => Some(x5u.to_owned()),
            Some(None) => return Err(header()),
        };
        // ATIS-1000074 makes `x5u` one of the four header parameters of
        // every SHAKEN PASSporT: it is what binds the signature to the
        // certificate the Identity header field's unsigned `info` names
        if shaken && x5u.is_none() {
            return Err(header());
        }
        Ok(Header { x5u, shaken })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tn(number: &str) -> Tn {
        Tn::new(number).unwrap()
    }

    fn shaken_claims() -> Claims {
        Claims {
            orig: tn("12155551212"),
            dest: Dest::tn(tn("12125551213")),
            iat: 1_443_208_345,
            shaken: Some(Shaken {
                attest: Attest::A,
                origid: OrigId::parse("123e4567-e89b-12d3-a456-426655440000").unwrap(),
            }),
        }
    }

    #[test]
    fn rfc8225_appendix_a_header() {
        assert_eq!(
            header_json("https://cert.example.org/passport.cer", false),
            r#"{"alg":"ES256","typ":"passport","x5u":"https://cert.example.org/passport.cer"}"#
        );
    }

    #[test]
    fn rfc8588_example_header_and_claims() {
        assert_eq!(
            header_json("https://cert.example.org/passport.cer", true),
            r#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://cert.example.org/passport.cer"}"#
        );
        assert_eq!(
            shaken_claims().to_json(),
            r#"{"attest":"A","dest":{"tn":["12125551213"]},"iat":1443208345,"orig":{"tn":"12155551212"},"origid":"123e4567-e89b-12d3-a456-426655440000"}"#
        );
    }

    #[test]
    fn plain_claims_with_uri_and_tn_destinations() {
        let claims = Claims {
            orig: tn("12155551212"),
            dest: Dest {
                tn: vec![tn("12125551213"), tn("12125551214")],
                uri: vec!["sip:alice@example.com".to_owned()],
            },
            iat: 1_443_208_345,
            shaken: None,
        };
        assert_eq!(
            claims.to_json(),
            r#"{"dest":{"tn":["12125551213","12125551214"],"uri":["sip:alice@example.com"]},"iat":1443208345,"orig":{"tn":"12155551212"}}"#
        );
        assert_eq!(
            Claims::from_json(claims.to_json().as_bytes(), false),
            Ok(claims)
        );
    }

    #[test]
    fn destinations_are_written_in_lexicographical_order() {
        // RFC 8225 §5.2.1: within "tn" and "uri", lexicographical order
        let claims = Claims {
            orig: tn("12155551212"),
            dest: Dest {
                tn: vec![tn("12125551214"), tn("12125551213")],
                uri: vec![
                    "sip:bob@example.com".to_owned(),
                    "sip:alice@example.com".to_owned(),
                ],
            },
            iat: 1_443_208_345,
            shaken: None,
        };
        assert_eq!(
            claims.to_json(),
            r#"{"dest":{"tn":["12125551213","12125551214"],"uri":["sip:alice@example.com","sip:bob@example.com"]},"iat":1443208345,"orig":{"tn":"12155551212"}}"#
        );
    }

    #[test]
    fn claims_round_trip_through_json() {
        let claims = shaken_claims();
        assert_eq!(
            Claims::from_json(claims.to_json().as_bytes(), true),
            Ok(claims)
        );
    }

    #[test]
    fn shaken_claims_need_attest_and_origid() {
        let bad = Err(Failure::Malformed(Malformed::Claims));
        let base = r#""dest":{"tn":["12125551213"]},"iat":1,"orig":{"tn":"12155551212"}"#;
        let no_attest = format!(r#"{{{base},"origid":"123e4567-e89b-12d3-a456-426655440000"}}"#);
        assert_eq!(Claims::from_json(no_attest.as_bytes(), true), bad);
        let no_origid = format!(r#"{{{base},"attest":"A"}}"#);
        assert_eq!(Claims::from_json(no_origid.as_bytes(), true), bad);
        let bad_attest =
            format!(r#"{{{base},"attest":"D","origid":"123e4567-e89b-12d3-a456-426655440000"}}"#);
        assert_eq!(Claims::from_json(bad_attest.as_bytes(), true), bad);
        let bad_origid = format!(r#"{{{base},"attest":"B","origid":"not-a-uuid"}}"#);
        assert_eq!(Claims::from_json(bad_origid.as_bytes(), true), bad);
        // without the extension, neither is looked at
        let plain = Claims::from_json(no_attest.as_bytes(), false).unwrap();
        assert_eq!(plain.shaken, None);
    }

    #[test]
    fn required_claims() {
        let bad = Err(Failure::Malformed(Malformed::Claims));
        for json in [
            r#"{"dest":{"tn":["1"]},"orig":{"tn":"2"}}"#,
            r#"{"dest":{"tn":["1"]},"iat":-1,"orig":{"tn":"2"}}"#,
            r#"{"dest":{"tn":["1"]},"iat":1.5,"orig":{"tn":"2"}}"#,
            r#"{"dest":{"tn":["1"]},"iat":"1","orig":{"tn":"2"}}"#,
            r#"{"dest":{"tn":["1"]},"iat":1}"#,
            r#"{"dest":{"tn":["1"]},"iat":1,"orig":{"uri":"sip:a@example.com"}}"#,
            r#"{"dest":{"tn":["1"]},"iat":1,"orig":{"tn":"+12155551212"}}"#,
            r#"{"dest":{"tn":["1"]},"iat":1,"orig":{"tn":2}}"#,
            r#"{"iat":1,"orig":{"tn":"2"}}"#,
            r#"{"dest":{},"iat":1,"orig":{"tn":"2"}}"#,
            r#"{"dest":{"tn":[]},"iat":1,"orig":{"tn":"2"}}"#,
            r#"{"dest":{"tn":"1"},"iat":1,"orig":{"tn":"2"}}"#,
            r#"{"dest":{"tn":[1]},"iat":1,"orig":{"tn":"2"}}"#,
            r#"{"dest":{"tn":["1-2"]},"iat":1,"orig":{"tn":"2"}}"#,
            r#"{"dest":{"uri":[1]},"iat":1,"orig":{"tn":"2"}}"#,
            r#"{"dest":["1"],"iat":1,"orig":{"tn":"2"}}"#,
        ] {
            assert_eq!(Claims::from_json(json.as_bytes(), false), bad, "{json}");
        }
        assert_eq!(
            Claims::from_json(b"[1]", false),
            Err(Failure::Malformed(Malformed::Json))
        );
        assert_eq!(
            Claims::from_json(b"{", false),
            Err(Failure::Malformed(Malformed::Json))
        );
    }

    #[test]
    fn unknown_claims_are_ignored() {
        let json = r#"{"dest":{"tn":["1"]},"iat":1,"orig":{"tn":"2"},"rcd":{"nam":"x"}}"#;
        assert_eq!(Claims::from_json(json.as_bytes(), false).unwrap().iat, 1);
    }

    #[test]
    fn header_rules() {
        let ok = |json: &str| Header::from_json(json.as_bytes());
        assert_eq!(
            ok(r#"{"alg":"ES256","typ":"passport","x5u":"https://a.example/c"}"#),
            Ok(Header {
                x5u: Some("https://a.example/c".to_owned()),
                shaken: false
            })
        );
        assert_eq!(
            ok(r#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://a.example/c"}"#),
            Ok(Header {
                x5u: Some("https://a.example/c".to_owned()),
                shaken: true
            })
        );
        assert_eq!(
            ok(r#"{"alg":"ES256","typ":"passport"}"#),
            Ok(Header {
                x5u: None,
                shaken: false
            })
        );
        assert_eq!(
            ok(r#"{"alg":"RS256","typ":"passport"}"#),
            Err(Failure::UnsupportedAlgorithm)
        );
        assert_eq!(
            ok(r#"{"alg":"ES256","ppt":"div","typ":"passport"}"#),
            Err(Failure::UnsupportedPpt)
        );
        let header = Err(Failure::Malformed(Malformed::Header));
        assert_eq!(
            ok(r#"{"alg":"ES256","ppt":"shaken","typ":"passport"}"#),
            header
        );
        assert_eq!(ok(r#"{"alg":"ES256"}"#), header);
        assert_eq!(ok(r#"{"alg":"ES256","typ":"JWT"}"#), header);
        assert_eq!(ok(r#"{"typ":"passport"}"#), header);
        assert_eq!(ok(r#"{"alg":256,"typ":"passport"}"#), header);
        assert_eq!(ok(r#"{"alg":"ES256","ppt":1,"typ":"passport"}"#), header);
        assert_eq!(ok(r#"{"alg":"ES256","typ":"passport","x5u":1}"#), header);
        assert_eq!(
            ok(r#"{"alg":"ES256","crit":["x"],"typ":"passport","x":1}"#),
            Err(Failure::Malformed(Malformed::Critical))
        );
        assert_eq!(ok("1"), Err(Failure::Malformed(Malformed::Json)));
        assert_eq!(ok("{"), Err(Failure::Malformed(Malformed::Json)));
    }

    #[test]
    fn telephone_numbers() {
        assert!(Tn::new("12155551212").is_ok());
        assert!(Tn::new("*67#").is_ok());
        assert!(Tn::new("123456789012345").is_ok());
        assert_eq!(Tn::new(""), Err(InvalidTn));
        assert_eq!(Tn::new("1234567890123456"), Err(InvalidTn));
        assert_eq!(Tn::new("+12155551212"), Err(InvalidTn));
        assert_eq!(Tn::new("215-555-1212"), Err(InvalidTn));
        assert_eq!(tn("12155551212").to_string(), "12155551212");
    }

    #[test]
    fn origid_text_form() {
        let origid = OrigId::parse("123E4567-E89B-12D3-A456-426655440000").unwrap();
        assert_eq!(origid.to_string(), "123e4567-e89b-12d3-a456-426655440000");
        assert_eq!(
            origid.as_bytes(),
            &[
                0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x55, 0x44,
                0x00, 0x00
            ]
        );
        assert_eq!(OrigId::from_bytes(*origid.as_bytes()), origid);
        for bad in [
            "",
            "123e4567e89b12d3a456426655440000",
            "123e4567-e89b-12d3-a456-42665544000",
            "123e4567-e89b-12d3-a456-4266554400000",
            "123e4567+e89b-12d3-a456-426655440000",
            "123e4567-e89b-12d3-a456-42665544000g",
        ] {
            assert_eq!(OrigId::parse(bad), Err(InvalidOrigId), "{bad}");
        }
    }

    #[test]
    fn attest_levels() {
        for (level, text) in [(Attest::A, "A"), (Attest::B, "B"), (Attest::C, "C")] {
            assert_eq!(level.as_str(), text);
            assert_eq!(Attest::parse(text), Some(level));
            assert_eq!(level.to_string(), text);
        }
        assert_eq!(Attest::parse("a"), None);
    }
}
