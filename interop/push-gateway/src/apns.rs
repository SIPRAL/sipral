// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A VoIP push through APNs, with token-based authentication.
//!
//! From Apple's "Establishing a token-based connection to APNs" and
//! "Sending notification requests to APNs": a POST to `/3/device/<token>`
//! over HTTP/2, `authorization: bearer <JWT>` where the JWT's header is
//! `{"alg":"ES256","kid":<Key ID>}` and its claims `{"iss":<Team ID>,
//! "iat":<seconds>}`, signed with the `.p8` key; `apns-push-type: voip` and
//! `apns-topic: <bundle>.voip` for a VoIP push. A token is used for at most
//! fifty minutes, inside Apple's twenty to sixty. The answer is 200 with an
//! `apns-id`, or a status with `{"reason": ...}`.
//!
//! RFC 8599 §10 puts the team and the topic in `pn-param`
//! (`<Team ID>.<bundle>.voip`) and the device token in `pn-prid`.
//!
//! Unproven against Apple with a real key: `probe` shows what Apple answers
//! to this request signed by a key it does not know, which is as far as a
//! machine with no Apple account can go.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::h2::{Request, Response, Tls};
use crate::json;
use crate::jwt::Signer;
use crate::push::{PushOutcome, PushRequest};

/// Where pushes for a build signed for development go.
pub(crate) const SANDBOX: &str = "api.sandbox.push.apple.com";
/// Where pushes for an App Store or TestFlight build go.
pub(crate) const PRODUCTION: &str = "api.push.apple.com";

/// How long one provider token is used before another is signed.
const TOKEN_LIFETIME: Duration = Duration::from_secs(50 * 60);

/// Seconds since the epoch.
pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The topic in a `pn-param`: everything after the Team ID (§10).
pub(crate) fn topic(param: &str) -> Option<&str> {
    param.split_once('.').map(|(_, topic)| topic)
}

/// A sender for one key.
pub(crate) struct Apns {
    signer: Signer,
    key_id: String,
    team: String,
    host: &'static str,
    token: Option<(String, u64)>,
}

impl Apns {
    /// A sender for `signer`, Apple's `key_id` for it, and the team it
    /// belongs to; to the sandbox or to production.
    pub(crate) fn new(signer: Signer, key_id: &str, team: &str, sandbox: bool) -> Self {
        Self {
            signer,
            key_id: key_id.to_owned(),
            team: team.to_owned(),
            host: if sandbox { SANDBOX } else { PRODUCTION },
            token: None,
        }
    }

    /// The host this sender talks to.
    pub(crate) const fn host(&self) -> &'static str {
        self.host
    }

    /// The provider token, signed again once it is fifty minutes old.
    pub(crate) fn provider_token(&mut self, now: u64) -> Result<String, String> {
        if let Some((token, issued)) = &self.token
            && now.saturating_sub(*issued) < TOKEN_LIFETIME.as_secs()
        {
            return Ok(token.clone());
        }
        let header = json::object(&[("alg", "ES256".to_owned()), ("kid", self.key_id.clone())]);
        let claims = format!("{{\"iss\":{},\"iat\":{now}}}", json::string(&self.team));
        let token = self.signer.token(&header, &claims)?;
        self.token = Some((token.clone(), now));
        Ok(token)
    }

    /// The request for one push.
    pub(crate) fn request(&self, push: &PushRequest, token: &str) -> Result<Request, String> {
        let param = push.param.as_deref().ok_or("no pn-param, so no topic")?;
        let topic = topic(param).ok_or("pn-param has no topic after the Team ID")?;
        if !push.prid.bytes().all(|byte| byte.is_ascii_hexdigit()) || push.prid.is_empty() {
            return Err("pn-prid is not a device token in hexadecimal".to_owned());
        }
        Ok(Request {
            authority: self.host.to_owned(),
            path: format!("/3/device/{}", push.prid),
            headers: vec![
                ("authorization".into(), format!("bearer {token}")),
                ("apns-push-type".into(), "voip".into()),
                ("apns-topic".into(), topic.to_owned()),
                ("apns-priority".into(), "10".into()),
                // a call that cannot ring now is not worth ringing later
                ("apns-expiration".into(), "0".into()),
                ("content-type".into(), "application/json".into()),
            ],
            body: push.payload().into_bytes(),
        })
    }

    /// Send one push.
    pub(crate) fn send(&mut self, tls: &Tls, push: &PushRequest) -> PushOutcome {
        let token = match self.provider_token(unix_now()) {
            Ok(token) => token,
            Err(why) => return PushOutcome::Failed(why),
        };
        let request = match self.request(push, &token) {
            Ok(request) => request,
            Err(why) => return PushOutcome::Failed(why),
        };
        match tls.send(self.host, 443, &request) {
            Ok(response) => describe(&response),
            Err(why) => PushOutcome::Failed(why),
        }
    }
}

/// What Apple's answer means.
pub(crate) fn describe(response: &Response) -> PushOutcome {
    if response.status == 200 {
        return PushOutcome::Accepted(format!(
            "APNs 200, apns-id {}",
            response.header("apns-id").unwrap_or("not given")
        ));
    }
    let reason = std::str::from_utf8(&response.body)
        .ok()
        .and_then(json::parse)
        .and_then(|body| {
            body.get("reason")
                .and_then(json::Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| "no reason given".to_owned());
    PushOutcome::Failed(format!("APNs {} {reason}", response.status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::tests::{decode64url, p8};
    use crate::push::PushKind;
    use ring::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};

    fn push() -> PushRequest {
        PushRequest {
            id: 7,
            provider: "apns".into(),
            prid: "00fc13adff785122b4ad28809a3420982341241421348097878e577c991de8f0".into(),
            param: Some("DEF123GHIJ.com.example.yourexampleapp.voip".into()),
            kind: PushKind::Call,
            caller: Some("sip:bob@example.com".into()),
            name: None,
            call_id: Some("a84b4c76e66710@pc33.example.com".into()),
        }
    }

    #[test]
    fn the_request_is_a_voip_push_to_the_topic_pn_param_names() {
        let mut apns = Apns::new(
            Signer::es256_pem(p8().as_bytes()).expect("key"),
            "ABC123DEFG",
            "DEF123GHIJ",
            true,
        );
        let token = apns.provider_token(1_437_179_036).expect("token");
        let request = apns.request(&push(), &token).expect("request");
        assert_eq!(request.authority, "api.sandbox.push.apple.com");
        assert_eq!(
            request.path,
            "/3/device/00fc13adff785122b4ad28809a3420982341241421348097878e577c991de8f0"
        );
        let field = |name: &str| {
            request
                .headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(field("apns-push-type").as_deref(), Some("voip"));
        assert_eq!(
            field("apns-topic").as_deref(),
            Some("com.example.yourexampleapp.voip")
        );
        assert_eq!(field("apns-priority").as_deref(), Some("10"));
        assert_eq!(field("authorization"), Some(format!("bearer {token}")));
        assert_eq!(
            request.body,
            br#"{"kind":"call","caller":"sip:bob@example.com","call-id":"a84b4c76e66710@pc33.example.com"}"#
        );
    }

    #[test]
    fn the_provider_token_is_apples_jwt_and_is_reused_for_fifty_minutes() {
        let mut apns = Apns::new(
            Signer::es256_pem(p8().as_bytes()).expect("key"),
            "ABC123DEFG",
            "DEF123GHIJ",
            false,
        );
        assert_eq!(apns.host(), "api.push.apple.com");
        let token = apns.provider_token(1_437_179_036).expect("token");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(
            decode64url(parts[0]),
            br#"{"alg":"ES256","kid":"ABC123DEFG"}"#
        );
        assert_eq!(
            decode64url(parts[1]),
            br#"{"iss":"DEF123GHIJ","iat":1437179036}"#
        );
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, apns.signer.public())
            .verify(
                format!("{}.{}", parts[0], parts[1]).as_bytes(),
                &decode64url(parts[2]),
            )
            .expect("signed by the key");
        assert_eq!(
            apns.provider_token(1_437_179_036 + 49 * 60).expect("again"),
            token
        );
        assert_ne!(
            apns.provider_token(1_437_179_036 + 50 * 60).expect("new"),
            token
        );
    }

    #[test]
    fn a_token_that_is_not_hex_and_a_param_with_no_topic_are_refused() {
        let apns = Apns::new(
            Signer::es256_pem(p8().as_bytes()).expect("key"),
            "K",
            "T",
            true,
        );
        let mut bad = push();
        bad.prid = "not/hex".into();
        assert!(apns.request(&bad, "t").is_err());
        let mut bad = push();
        bad.param = Some("DEF123GHIJ".into());
        assert!(apns.request(&bad, "t").is_err());
    }

    #[test]
    fn apples_answers_read() {
        let accepted = Response {
            status: 200,
            headers: vec![(
                "apns-id".into(),
                "eabeae54-14a8-11e5-b60b-1697f925ec7b".into(),
            )],
            body: Vec::new(),
        };
        assert_eq!(
            describe(&accepted),
            PushOutcome::Accepted("APNs 200, apns-id eabeae54-14a8-11e5-b60b-1697f925ec7b".into())
        );
        let gone = Response {
            status: 410,
            headers: Vec::new(),
            body: br#"{"reason":"Unregistered","timestamp":1454402113}"#.to_vec(),
        };
        assert_eq!(
            describe(&gone),
            PushOutcome::Failed("APNs 410 Unregistered".into())
        );
    }
}
