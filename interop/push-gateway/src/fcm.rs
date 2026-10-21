// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A high-priority data message through FCM's HTTP v1 API.
//!
//! From Google's "Using OAuth 2.0 for Server to Server Applications" and
//! the FCM v1 reference: the service account signs a JWT with RS256 --
//! `iss` its `client_email`, `scope`
//! `https://www.googleapis.com/auth/firebase.messaging`, `aud` its
//! `token_uri`, `iat` and `exp` an hour apart -- and trades it at `token_uri`
//! (`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`) for an access
//! token. The message is a POST to
//! `/v1/projects/<project>/messages:send` with `Authorization: Bearer`, a
//! `token`, string-valued `data`, and `android.priority` `high`, which is what
//! wakes a device in Doze. The answer is the message's `name`, or a
//! `google.rpc.Status` whose `details` carry FCM's own `errorCode`.
//!
//! RFC 8599 §11 puts the project ID in `pn-param` and the registration token
//! in `pn-prid`.
//!
//! Unproven against Google with a real service account: `probe` shows what
//! Google answers to these requests without one.

use std::fmt::Write as _;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::apns::unix_now;
use crate::h2::{Request, Response, Tls};
use crate::json::{self, Value};
use crate::jwt::Signer;
use crate::push::{PushOutcome, PushRequest};

/// The OAuth 2.0 scope sending needs.
pub(crate) const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// The host messages are sent to.
pub(crate) const HOST: &str = "fcm.googleapis.com";

/// A service account file, the parts of it that are used.
pub(crate) struct ServiceAccount {
    /// `client_email`: the issuer.
    pub(crate) client_email: String,
    /// `private_key_id`: the `kid`.
    pub(crate) key_id: String,
    /// `token_uri`: where the assertion is traded.
    pub(crate) token_uri: String,
    /// `project_id`: what `pn-param` has to name.
    pub(crate) project_id: String,
    signer: Signer,
}

impl ServiceAccount {
    /// Read the JSON Google hands out for a service account key.
    pub(crate) fn from_json(text: &str) -> Result<Self, String> {
        let document = json::parse(text).ok_or("the service account file is not JSON")?;
        let field = |name: &str| {
            document
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("the service account file has no {name}"))
        };
        Ok(Self {
            client_email: field("client_email")?,
            key_id: field("private_key_id")?,
            token_uri: field("token_uri")?,
            project_id: field("project_id")?,
            signer: Signer::rs256_pem(field("private_key")?.as_bytes())?,
        })
    }

    /// Read one from a file.
    pub(crate) fn from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        Self::from_json(&text)
    }
}

/// `https://host[:port]/path` taken apart.
pub(crate) fn split_https(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("{url} is not https"))?;
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, "/".to_owned()), |(a, p)| (a, format!("/{p}")));
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, port.parse().map_err(|_| format!("{url}: bad port"))?),
        None => (authority, 443),
    };
    Ok((host.to_owned(), port, path))
}

/// `application/x-www-form-urlencoded` for one value (the WHATWG URL
/// standard's form, which Google reads).
fn form_escape(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'*') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// A sender for one service account.
pub(crate) struct Fcm {
    account: ServiceAccount,
    ttl: Duration,
    access: Option<(String, Instant)>,
}

impl Fcm {
    /// A sender whose messages are dropped by FCM if they cannot be
    /// delivered within `ttl`.
    pub(crate) const fn new(account: ServiceAccount, ttl: Duration) -> Self {
        Self {
            account,
            ttl,
            access: None,
        }
    }

    /// The signed assertion (RFC 7523 §2.1).
    pub(crate) fn assertion(&self, now: u64) -> Result<String, String> {
        let header = json::object(&[
            ("alg", "RS256".to_owned()),
            ("typ", "JWT".to_owned()),
            ("kid", self.account.key_id.clone()),
        ]);
        let claims = format!(
            "{{\"iss\":{},\"scope\":{},\"aud\":{},\"iat\":{now},\"exp\":{}}}",
            json::string(&self.account.client_email),
            json::string(SCOPE),
            json::string(&self.account.token_uri),
            now + 3600
        );
        self.account.signer.token(&header, &claims)
    }

    /// The request for one push.
    pub(crate) fn request(&self, push: &PushRequest, access: &str) -> Request {
        message_request(&self.account.project_id, self.ttl, push, access)
    }

    fn access_token(&mut self, tls: &Tls) -> Result<String, String> {
        if let Some((token, until)) = &self.access
            && Instant::now() < *until
        {
            return Ok(token.clone());
        }
        let assertion = self.assertion(unix_now())?;
        let (host, port, request) = token_request(&self.account.token_uri, &assertion)?;
        let response = tls.send(&host, port, &request)?;
        let (token, lifetime) = token_answer(&response)?;
        // a minute early, so a token is never sent as it lapses
        self.access = Some((
            token.clone(),
            Instant::now() + Duration::from_secs(lifetime.saturating_sub(60)),
        ));
        Ok(token)
    }

    /// Send one push.
    pub(crate) fn send(&mut self, tls: &Tls, push: &PushRequest) -> PushOutcome {
        if push.param.as_deref() != Some(self.account.project_id.as_str()) {
            return PushOutcome::Failed("pn-param names another project".to_owned());
        }
        let access = match self.access_token(tls) {
            Ok(access) => access,
            Err(why) => return PushOutcome::Failed(format!("no access token: {why}")),
        };
        match tls.send(HOST, 443, &self.request(push, &access)) {
            Ok(response) => describe(&response),
            Err(why) => PushOutcome::Failed(why),
        }
    }
}

/// The request that trades an assertion for an access token at
/// `token_uri`, and the host and port it goes to.
pub(crate) fn token_request(
    token_uri: &str,
    assertion: &str,
) -> Result<(String, u16, Request), String> {
    let (host, port, path) = split_https(token_uri)?;
    Ok((
        host.clone(),
        port,
        Request {
            authority: host,
            path,
            headers: vec![(
                "content-type".into(),
                "application/x-www-form-urlencoded".into(),
            )],
            body: format!(
                "grant_type={}&assertion={}",
                form_escape("urn:ietf:params:oauth:grant-type:jwt-bearer"),
                form_escape(assertion)
            )
            .into_bytes(),
        },
    ))
}

/// The request for one push to a project, with an access token, kept by
/// FCM for `ttl` at most.
pub(crate) fn message_request(
    project: &str,
    ttl: Duration,
    push: &PushRequest,
    access: &str,
) -> Request {
    let ttl = format!("{}s", ttl.as_secs());
    let body = format!(
        "{{\"message\":{{\"token\":{},\"data\":{},\"android\":{{\"priority\":\"high\",\"ttl\":{}}}}}}}",
        json::string(&push.prid),
        push.payload(),
        json::string(&ttl)
    );
    Request {
        authority: HOST.to_owned(),
        path: format!("/v1/projects/{project}/messages:send"),
        headers: vec![
            ("authorization".into(), format!("Bearer {access}")),
            ("content-type".into(), "application/json".into()),
        ],
        body: body.into_bytes(),
    }
}

/// The access token and its lifetime in seconds, from the token endpoint's
/// answer, or what it said instead.
pub(crate) fn token_answer(response: &Response) -> Result<(String, u64), String> {
    let body = std::str::from_utf8(&response.body)
        .ok()
        .and_then(json::parse)
        .ok_or_else(|| format!("{} with a body that is not JSON", response.status))?;
    if response.status == 200
        && let Some(token) = body.get("access_token").and_then(Value::as_str)
    {
        let lifetime = body
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(3600);
        return Ok((token.to_owned(), lifetime));
    }
    let error = body
        .get("error")
        .and_then(Value::as_str)
        .unwrap_or("no error named");
    let description = body
        .get("error_description")
        .and_then(Value::as_str)
        .unwrap_or("");
    Err(format!("{} {error} {description}", response.status)
        .trim()
        .to_owned())
}

/// What FCM's answer means.
pub(crate) fn describe(response: &Response) -> PushOutcome {
    let body = std::str::from_utf8(&response.body)
        .ok()
        .and_then(json::parse);
    if response.status == 200 {
        let name = body
            .as_ref()
            .and_then(|body| body.get("name").and_then(Value::as_str).map(str::to_owned))
            .unwrap_or_else(|| "no name given".to_owned());
        return PushOutcome::Accepted(format!("FCM 200, {name}"));
    }
    let error = body.as_ref().and_then(|body| body.get("error"));
    let status = error
        .and_then(|error| error.get("status").and_then(Value::as_str))
        .unwrap_or("no status");
    let code = error
        .and_then(|error| error.get("details"))
        .and_then(|details| match details {
            Value::Array(items) => items
                .iter()
                .find_map(|item| item.get("errorCode").and_then(Value::as_str)),
            _ => None,
        });
    PushOutcome::Failed(match code {
        Some(code) => format!("FCM {} {status} {code}", response.status),
        None => format!("FCM {} {status}", response.status),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::tests::{decode64url, rsa_pem};
    use crate::push::PushKind;

    fn account() -> ServiceAccount {
        let document = format!(
            "{{\"type\":\"service_account\",\"project_id\":\"lab-project\",\"private_key_id\":\"k1\",\
             \"private_key\":{},\"client_email\":\"gw@lab-project.iam.example.com\",\
             \"token_uri\":\"https://oauth2.googleapis.com/token\"}}",
            json::string(&rsa_pem())
        );
        ServiceAccount::from_json(&document).expect("an account")
    }

    #[test]
    fn the_assertion_is_googles_jwt() {
        let fcm = Fcm::new(account(), Duration::from_secs(20));
        let assertion = fcm.assertion(1_700_000_000).expect("signed");
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(
            decode64url(parts[0]),
            br#"{"alg":"RS256","typ":"JWT","kid":"k1"}"#
        );
        assert_eq!(
            String::from_utf8(decode64url(parts[1])).expect("utf-8"),
            "{\"iss\":\"gw@lab-project.iam.example.com\",\
             \"scope\":\"https://www.googleapis.com/auth/firebase.messaging\",\
             \"aud\":\"https://oauth2.googleapis.com/token\",\"iat\":1700000000,\"exp\":1700003600}"
        );
        assert_eq!(decode64url(parts[2]).len(), 256, "a 2048-bit signature");
        let (host, port, request) =
            token_request(&fcm.account.token_uri, &assertion).expect("request");
        assert_eq!(
            (host.as_str(), port, request.path.as_str()),
            ("oauth2.googleapis.com", 443, "/token")
        );
        let body = String::from_utf8(request.body).expect("utf-8");
        assert!(body.starts_with(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        ));
        assert!(body.ends_with(&assertion), "base64url needs no escaping");
    }

    #[test]
    fn the_message_is_a_high_priority_data_message() {
        let fcm = Fcm::new(account(), Duration::from_secs(20));
        let push = PushRequest {
            id: 1,
            provider: "fcm".into(),
            prid: "bk3RNwTe3H0:CI2k_HHwgIpoDKCIZvvDMExUdFQ3P1".into(),
            param: Some("lab-project".into()),
            kind: PushKind::Call,
            caller: Some("sip:bob@example.com".into()),
            name: Some("Bob".into()),
            call_id: Some("a84b4c76e66710@pc33.example.com".into()),
        };
        let request = fcm.request(&push, "ya29.token");
        assert_eq!(request.authority, "fcm.googleapis.com");
        assert_eq!(request.path, "/v1/projects/lab-project/messages:send");
        assert!(
            request
                .headers
                .contains(&("authorization".into(), "Bearer ya29.token".into()))
        );
        let body = json::parse(std::str::from_utf8(&request.body).expect("utf-8")).expect("json");
        let message = body.get("message").expect("message");
        assert_eq!(
            message.get("token").and_then(Value::as_str),
            Some("bk3RNwTe3H0:CI2k_HHwgIpoDKCIZvvDMExUdFQ3P1")
        );
        let data = message.get("data").expect("data");
        assert_eq!(
            data.get("caller").and_then(Value::as_str),
            Some("sip:bob@example.com")
        );
        assert_eq!(data.get("kind").and_then(Value::as_str), Some("call"));
        assert_eq!(
            data.get("call-id").and_then(Value::as_str),
            Some("a84b4c76e66710@pc33.example.com")
        );
        let android = message.get("android").expect("android");
        assert_eq!(
            android.get("priority").and_then(Value::as_str),
            Some("high")
        );
        assert_eq!(android.get("ttl").and_then(Value::as_str), Some("20s"));
    }

    #[test]
    fn googles_answers_read() {
        let token = Response {
            status: 200,
            headers: Vec::new(),
            body: br#"{"access_token":"ya29.c","expires_in":3599,"token_type":"Bearer"}"#.to_vec(),
        };
        assert_eq!(token_answer(&token), Ok(("ya29.c".to_owned(), 3599)));
        let refused = Response {
            status: 400,
            headers: Vec::new(),
            body: br#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#
                .to_vec(),
        };
        assert_eq!(
            token_answer(&refused),
            Err("400 invalid_grant Invalid JWT Signature.".to_owned())
        );
        let gone = Response {
            status: 404,
            headers: Vec::new(),
            body: br#"{"error":{"code":404,"message":"Requested entity was not found.","status":"NOT_FOUND",
                "details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}"#
                .to_vec(),
        };
        assert_eq!(
            describe(&gone),
            PushOutcome::Failed("FCM 404 NOT_FOUND UNREGISTERED".into())
        );
        let sent = Response {
            status: 200,
            headers: Vec::new(),
            body:
                br#"{"name":"projects/lab-project/messages/0:1500415314455276%31bd1c9631bd1c96"}"#
                    .to_vec(),
        };
        assert_eq!(
            describe(&sent),
            PushOutcome::Accepted(
                "FCM 200, projects/lab-project/messages/0:1500415314455276%31bd1c9631bd1c96".into()
            )
        );
    }

    #[test]
    fn urls_and_accounts() {
        assert_eq!(
            split_https("https://oauth2.googleapis.com/token"),
            Ok(("oauth2.googleapis.com".to_owned(), 443, "/token".to_owned()))
        );
        assert_eq!(
            split_https("https://localhost:8443/a/b"),
            Ok(("localhost".to_owned(), 8443, "/a/b".to_owned()))
        );
        assert!(split_https("http://x/").is_err());
        assert!(ServiceAccount::from_json("{\"project_id\":\"p\"}").is_err());
    }
}
