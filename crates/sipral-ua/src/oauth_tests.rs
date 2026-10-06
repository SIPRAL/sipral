// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! OAuth 2.0 access tokens at the account's server (RFC 8898): a `Bearer`
//! challenge reported with where a token comes from, answered with the token
//! the application supplied, and a refused token never offered again.

use std::time::Instant;

use sipral_core::msg::HeaderName;

use crate::tests::{account, agent, deliver, events, header, reply, sent, transmits};
use crate::{
    BearerChallenge, BearerError, Credentials, RegistrationFailure, RegistrationState, UaError,
    UaEvent, UserAgent,
};

const AS: &str = "https://as.example.com/oauth2";

fn bearer(error: Option<&str>) -> String {
    let error = error.map_or(String::new(), |code| format!(", error=\"{code}\""));
    format!(
        "WWW-Authenticate: Bearer realm=\"example.com\", scope=\"sip:register\", \
         authz_server=\"{AS}\"{error}\r\n"
    )
}

fn wanted(seen: &[UaEvent]) -> Option<BearerChallenge> {
    seen.iter().find_map(|event| match event {
        UaEvent::TokenRequired { challenge, .. } => Some(challenge.clone()),
        _ => None,
    })
}

fn failed(seen: &[UaEvent]) -> bool {
    seen.iter().any(|event| {
        matches!(
            event,
            UaEvent::RegistrationFailed {
                reason: RegistrationFailure::BadCredentials,
                ..
            }
        )
    })
}

fn authorization(request: &[u8]) -> String {
    String::from_utf8_lossy(&header(request, HeaderName::Authorization)).into_owned()
}

fn granted(agent: &mut UserAgent, request: &[u8], now: Instant) {
    deliver(
        agent,
        &reply(
            request,
            200,
            "OK",
            "Contact: <sip:alice@192.0.2.1>;expires=3600\r\n",
        ),
        now,
    );
}

#[test]
fn a_bearer_challenge_asks_the_application_for_a_token_and_the_token_answers_it() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());

    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    assert!(authorization(&first).is_empty(), "nothing to offer yet");
    deliver(
        &mut agent,
        &reply(&first, 401, "Unauthorized", &bearer(None)),
        t0,
    );
    assert!(transmits(&mut agent).is_empty(), "no token, no retry");
    let seen = events(&mut agent);
    let challenge = wanted(&seen).expect("the application is asked for a token");
    assert_eq!(challenge.authz_server.as_deref(), Some(AS));
    assert_eq!(challenge.scope.as_deref(), Some("sip:register"));
    assert_eq!(&*challenge.realm, "example.com");
    assert_eq!(challenge.error, None);
    assert!(!challenge.proxy);
    assert!(failed(&seen), "the refusal settles meanwhile");

    agent
        .set_access_token(id, Some("eyJhbGciOiJIUzI1NiJ9.e30.c2ln"))
        .expect("a token");
    agent.register(id, t0).expect("the REGISTER goes again");
    let second = sent(&mut agent);
    assert_eq!(
        authorization(&second),
        "Bearer eyJhbGciOiJIUzI1NiJ9.e30.c2ln",
        "the cached challenge is answered ahead of being asked (RFC 3261 section 22.2)"
    );
    granted(&mut agent, &second, t0);
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
}

#[test]
fn a_token_set_before_the_challenge_answers_it_on_the_retry() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(
        account().credentials(Credentials::bearer("first.token").expect("a token")),
    );
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(&first, 401, "Unauthorized", &bearer(None)),
        t0,
    );
    let retry = sent(&mut agent);
    assert_eq!(authorization(&retry), "Bearer first.token");
    assert!(wanted(&events(&mut agent)).is_none(), "nothing to ask for");
    granted(&mut agent, &retry, t0);
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
}

#[test]
fn an_invalid_token_is_never_offered_again_and_a_new_one_is_asked_for() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(
        account().credentials(Credentials::bearer("expired.token").expect("a token")),
    );
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    deliver(
        &mut agent,
        &reply(&first, 401, "Unauthorized", &bearer(None)),
        t0,
    );
    let retry = sent(&mut agent);
    assert_eq!(authorization(&retry), "Bearer expired.token");
    events(&mut agent);

    // RFC 6750 section 3.1: "expired, revoked, malformed, or invalid"
    deliver(
        &mut agent,
        &reply(
            &retry,
            401,
            "Unauthorized",
            &bearer(Some("invalid_token")),
        ),
        t0,
    );
    assert!(
        transmits(&mut agent).is_empty(),
        "the refused token is not sent a second time"
    );
    let seen = events(&mut agent);
    let challenge = wanted(&seen).expect("a new token is asked for");
    assert_eq!(challenge.error, Some(BearerError::InvalidToken));
    assert!(failed(&seen));

    // and not ahead of a challenge either
    agent.register(id, t0).expect("the REGISTER goes");
    let again = sent(&mut agent);
    assert!(authorization(&again).is_empty(), "{}", authorization(&again));
    events(&mut agent);

    agent
        .set_access_token(id, Some("fresh.token"))
        .expect("a token");
    deliver(
        &mut agent,
        &reply(&again, 401, "Unauthorized", &bearer(None)),
        t0,
    );
    let answered = sent(&mut agent);
    assert_eq!(authorization(&answered), "Bearer fresh.token");
    granted(&mut agent, &answered, t0);
    assert_eq!(
        agent.registration_state(id),
        Some(RegistrationState::Registered)
    );
}

#[test]
fn offered_both_schemes_for_one_realm_the_token_answers_and_the_password_stays_home() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(
        account().credentials(
            Credentials::new("alice", "open sesame")
                .with_access_token("the.token")
                .expect("a token"),
        ),
    );
    agent.register(id, t0).expect("the REGISTER goes");
    let first = sent(&mut agent);
    let both = format!(
        "WWW-Authenticate: Digest realm=\"example.com\", nonce=\"n1\", qop=\"auth\"\r\n{}",
        bearer(None)
    );
    deliver(&mut agent, &reply(&first, 401, "Unauthorized", &both), t0);
    let retry = sent(&mut agent);
    let fields: Vec<String> = crate::tests::with(&retry, |message| {
        message
            .header_values(HeaderName::Authorization)
            .map(|value| String::from_utf8_lossy(value).into_owned())
            .collect()
    });
    assert_eq!(fields, vec!["Bearer the.token".to_owned()]);

    // without a token the same challenge is answered with the password
    agent.set_access_token(id, None).expect("taken away");
    agent.register(id, t0).expect("the REGISTER goes");
    let digest = sent(&mut agent);
    assert!(authorization(&digest).starts_with("Digest "));
}

#[test]
fn a_token_that_is_not_a_b64token_is_refused_and_nothing_changes() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    assert_eq!(
        agent.set_access_token(id, Some("two words")),
        Err(UaError::InvalidAccessToken)
    );
    assert_eq!(
        agent.set_access_token(id, Some("a\r\nVia: x")),
        Err(UaError::InvalidAccessToken)
    );
    assert!(agent.account(id).is_some());
}
