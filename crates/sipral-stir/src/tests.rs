// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Signing and verifying end to end, against the throwaway PKI of
//! `testpki`, and every way a verification can fail.

use p256::ecdsa::Signature;
use p256::ecdsa::signature::Signer as _;

use crate::base64;
use crate::testpki::{
    self, DIGITAL_SIGNATURE, ECDSA_WITH_SHA384, KEY_CERT_SIGN, NOT_AFTER, NOT_BEFORE, NOW, ORIG,
    Pki, pem,
};
use crate::*;

const X5U: &str = "https://cert.example.org/passport.cer";

fn tn(number: &str) -> Tn {
    Tn::new(number).unwrap()
}

fn origid() -> OrigId {
    OrigId::parse("123e4567-e89b-12d3-a456-426655440000").unwrap()
}

fn claims(iat: u64) -> Claims {
    Claims {
        orig: tn(ORIG),
        dest: Dest::tn(tn("12125551213")),
        iat,
        shaken: Some(Shaken {
            attest: Attest::A,
            origid: origid(),
        }),
    }
}

fn signer() -> Signer {
    Signer::new(&[0x33; 32], X5U).unwrap()
}

fn anchors(pki: &Pki) -> TrustAnchors {
    let mut anchors = TrustAnchors::new();
    anchors.add(&pki.root).unwrap();
    anchors
}

/// Verify `identity` against `chain` under the default policy, at `NOW`.
fn verdict(identity: &str, chain: &[u8], pki: &Pki) -> Verdict {
    match Verifier::default().start(identity, None) {
        Ok(pending) => pending.verify(chain, &anchors(pki), NOW),
        Err(failure) => Verdict::Invalid(failure),
    }
}

fn failure(identity: &str, chain: &[u8], pki: &Pki) -> Failure {
    match verdict(identity, chain, pki) {
        Verdict::Invalid(failure) => failure,
        Verdict::Valid(verified) => panic!("verified: {verified:?}"),
    }
}

fn start_failure(identity: &str, from_request: Option<&Claims>) -> Failure {
    Verifier::default()
        .start(identity, from_request)
        .map(|pending| panic!("started: {pending:?}"))
        .unwrap_err()
}

/// A PASSporT whose header and claims are these JSON texts, as they are,
/// signed with the signing certificate's key.
fn hand_made(header: &str, claims: &str, params: &str) -> String {
    let header = base64::encode_url(header.as_bytes());
    let claims = base64::encode_url(claims.as_bytes());
    let signature: Signature = testpki::key(0x33).sign(format!("{header}.{claims}").as_bytes());
    let signature = base64::encode_url(&signature.to_bytes());
    format!("{header}.{claims}.{signature};info=<{X5U}>{params}")
}

fn chain_with_leaf(pki: &Pki, leaf: &testpki::Spec) -> Vec<u8> {
    [leaf.build(&pki.intermediate_key), pki.intermediate.clone()].concat()
}

fn chain_with_intermediate(pki: &Pki, intermediate: &testpki::Spec) -> Vec<u8> {
    [pki.leaf.clone(), intermediate.build(&pki.root_key)].concat()
}

const HEADER: &str = r#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://cert.example.org/passport.cer"}"#;
const CLAIMS: &str = r#"{"attest":"A","dest":{"tn":["12125551213"]},"iat":1790000000,"orig":{"tn":"12155551212"},"origid":"123e4567-e89b-12d3-a456-426655440000"}"#;

#[test]
fn the_rfc8588_example_is_what_is_signed() {
    let identity = signer().identity(&claims(1_443_208_345)).unwrap();
    let mut segments = identity.split(['.', ';']);
    let header = base64::decode_url(segments.next().unwrap().as_bytes()).unwrap();
    let payload = base64::decode_url(segments.next().unwrap().as_bytes()).unwrap();
    assert_eq!(
        String::from_utf8(header).unwrap(),
        r#"{"alg":"ES256","ppt":"shaken","typ":"passport","x5u":"https://cert.example.org/passport.cer"}"#
    );
    assert_eq!(
        String::from_utf8(payload).unwrap(),
        r#"{"attest":"A","dest":{"tn":["12125551213"]},"iat":1443208345,"orig":{"tn":"12155551212"},"origid":"123e4567-e89b-12d3-a456-426655440000"}"#
    );
    assert!(
        identity.ends_with(";info=<https://cert.example.org/passport.cer>;alg=ES256;ppt=shaken")
    );
    // RFC 8225 Appendix A's header, and its first segment as the RFC shows it
    assert_eq!(
        base64::encode_url(passport::header_json(X5U, false).as_bytes()),
        "eyJhbGciOiJFUzI1NiIsInR5cCI6InBhc3Nwb3J0IiwieDV1IjoiaHR0cHM6Ly9jZXJ0LmV4YW1wbGUub3JnL3Bhc3Nwb3J0LmNlciJ9"
    );
}

#[test]
fn a_shaken_passport_round_trips() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let pending = Verifier::default().start(&identity, None).unwrap();
    assert_eq!(pending.certificate_url(), X5U);
    assert_eq!(pending.claims(), &claims(NOW));
    let verdict = pending.verify(&pki.chain(), &anchors(&pki), NOW);
    assert_eq!(
        verdict,
        Verdict::Valid(Verified {
            orig: tn(ORIG),
            dest: Dest::tn(tn("12125551213")),
            iat: NOW,
            attest: Some(Attest::A),
            origid: Some(origid()),
            x5u: X5U.to_owned(),
            coverage: Coverage::Number,
        })
    );
    assert_eq!(verdict.verstat(), Verstat::TnValidationPassed);
    assert_eq!(verdict.sip_response(), None);
}

/// The key a deployment keeps is PEM more often than a bare scalar: a
/// signer made from it signs what the one made from the scalar signs.
#[test]
fn a_signer_takes_its_key_in_the_form_it_is_kept() {
    let scalar = [0x33; 32];
    // RFC 5915 §3: version 1, the key, the curve
    let mut sec1 = crate::der::write(0x02, &[1]);
    sec1.extend(crate::der::write(0x04, &scalar));
    sec1.extend(crate::der::write(
        0xa0,
        &crate::der::write(0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
    ));
    let sec1 = crate::der::write(0x30, &sec1);
    // the label is spliced in, so that the source holds no armoured key a
    // secret scanner would take for a real one
    let label = "EC PRIVATE KEY";
    let pem = format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        base64::encode_standard(&sec1)
    );
    let from_pem = Signer::from_key(pem.as_bytes(), X5U).unwrap();
    assert_eq!(from_pem.public_key(), signer().public_key());
    assert_eq!(from_pem.certificate_url(), X5U);
    let pki = Pki::new();
    let identity = from_pem.identity(&claims(NOW)).unwrap();
    assert!(matches!(
        verdict(&identity, &pki.chain(), &pki),
        Verdict::Valid(_)
    ));
    assert_eq!(
        Signer::from_key(b"-----BEGIN PRIVATE KEY-----", X5U).unwrap_err(),
        SignError::InvalidKey
    );
    assert_eq!(
        Signer::from_key(&[0u8; 32], X5U).unwrap_err(),
        SignError::InvalidKey,
        "zero is not a scalar"
    );
}

/// RFC 8224 §8.3's first step: the `+` and the visual separators go, and a
/// letter means the user part was never a number.
#[test]
fn numbers_are_canonicalised_as_rfc_8224_section_8_3_says() {
    assert_eq!(
        Tn::canonical("+1 (215) 555-1212").unwrap().as_str(),
        "12155551212"
    );
    assert_eq!(
        Tn::canonical("1.215.555.1212").unwrap().as_str(),
        "12155551212"
    );
    assert_eq!(Tn::canonical("*67#").unwrap().as_str(), "*67#");
    assert_eq!(Tn::canonical("alice"), Err(passport::InvalidTn));
    assert_eq!(Tn::canonical("+"), Err(passport::InvalidTn));
    assert_eq!(Tn::canonical("*#"), Err(passport::InvalidTn), "no digit");
    assert_eq!(
        Tn::canonical("1234567890123456"),
        Err(passport::InvalidTn),
        "sixteen"
    );
    assert_eq!(
        Tn::canonical("12+34"),
        Err(passport::InvalidTn),
        "a + inside"
    );
}

/// RFC 8224 §8.5: `scheme ":" user "@" host`, everything after the host
/// and the password dropped, lower case, unreserved escapes decoded.
#[test]
fn sip_uris_are_canonicalised_as_rfc_8224_section_8_5_says() {
    for (written, canonical) in [
        ("sip:alice@example.com", "sip:alice@example.com"),
        (
            "SIP:Alice:secret@Biloxi.example.com:5061;transport=tcp?Subject=hi",
            "sip:alice@biloxi.example.com",
        ),
        (
            "sips:bob@biloxi.example.com;lr",
            "sips:bob@biloxi.example.com",
        ),
        ("sip:%61lice@example.com", "sip:alice@example.com"),
        ("sip:a%2fb@example.com", "sip:a%2Fb@example.com"),
        ("sip:carol@[2001:DB8::1]:5060", "sip:carol@[2001:db8::1]"),
        ("sip:example.com:5060;user=phone", "sip:example.com"),
        (" sip:dave@192.0.2.1 ", "sip:dave@192.0.2.1"),
        ("TEL:+1-215-555-1212", "tel:+1-215-555-1212"),
        ("https://example.com/X", "https://example.com/X"),
    ] {
        assert_eq!(canonical_uri(written), canonical, "{written}");
    }
    let dest = Dest::uri("sip:Alice@Biloxi.example.com:5060;transport=udp");
    assert_eq!(dest.uri, ["sip:alice@biloxi.example.com"]);
    assert!(dest.names_uri("sip:alice@biloxi.example.com;user=phone"));
    assert!(dest.names_uri("SIP:ALICE@BILOXI.example.com"));
    assert!(!dest.names_uri("sip:mallory@example.com"));
    assert!(!dest.names_number(&tn("12125551213")));
    let numbers = Dest::tn(tn("12125551213"));
    assert!(numbers.names_number(&tn("12125551213")));
    assert!(!numbers.names_uri("sip:12125551213@example.com"));
}

/// The signer writes each `dest.uri` in the canonical form of RFC 8224
/// §8.5, however the claims gave it; what is signed is what a verifier
/// rebuilding a compact form from the request's To derives.
#[test]
fn the_signer_writes_dest_uri_canonical() {
    let pki = Pki::new();
    let mut to_a_name = claims(NOW);
    to_a_name.dest = Dest {
        tn: Vec::new(),
        uri: vec!["sip:Alice:pw@Biloxi.example.com:5070;transport=tcp".to_owned()],
    };
    let identity = signer().identity(&to_a_name).unwrap();
    let claims_segment = identity.split('.').nth(1).unwrap();
    let json = String::from_utf8(base64::decode_url(claims_segment.as_bytes()).unwrap()).unwrap();
    assert!(
        json.contains(r#""dest":{"uri":["sip:alice@biloxi.example.com"]}"#),
        "{json}"
    );
    let Verdict::Valid(verified) = verdict(&identity, &pki.chain(), &pki) else {
        panic!("not valid");
    };
    assert_eq!(verified.dest.uri, ["sip:alice@biloxi.example.com"]);

    // the compact form verifies against claims rebuilt from the request's
    // own To, written however that To was written
    let compact = signer().identity_compact(&to_a_name).unwrap();
    let mut rebuilt = to_a_name.clone();
    rebuilt.dest = Dest::uri("sip:alice@biloxi.example.com;user=ip");
    let pending = Verifier::default().start(&compact, Some(&rebuilt)).unwrap();
    assert!(matches!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Valid(_)
    ));
}

#[test]
fn a_pem_chain_verifies_too() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let chain = format!("{}{}", pem(&pki.leaf), pem(&pki.intermediate));
    assert!(matches!(
        verdict(&identity, chain.as_bytes(), &pki),
        Verdict::Valid(_)
    ));
}

#[test]
fn the_root_may_ride_along_and_the_issuers_come_in_any_order() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let chain = [pki.leaf.clone(), pki.root.clone(), pki.intermediate.clone()].concat();
    assert!(matches!(
        verdict(&identity, &chain, &pki),
        Verdict::Valid(_)
    ));
}

#[test]
fn a_plain_passport_round_trips() {
    let pki = Pki::new();
    let mut plain = claims(NOW);
    plain.shaken = None;
    plain.dest.uri.push("sip:alice@example.com".to_owned());
    let identity = signer().identity(&plain).unwrap();
    assert!(!identity.contains("ppt"));
    let Verdict::Valid(verified) = verdict(&identity, &pki.chain(), &pki) else {
        panic!("not valid");
    };
    assert_eq!(verified.attest, None);
    assert_eq!(verified.origid, None);
    assert_eq!(verified.dest, plain.dest);
}

#[test]
fn every_attestation_level_round_trips() {
    let pki = Pki::new();
    for level in [Attest::A, Attest::B, Attest::C] {
        let mut attested = claims(NOW);
        attested.shaken = Some(Shaken {
            attest: level,
            origid: origid(),
        });
        let identity = signer().identity(&attested).unwrap();
        let Verdict::Valid(verified) = verdict(&identity, &pki.chain(), &pki) else {
            panic!("not valid");
        };
        assert_eq!(verified.attest, Some(level));
    }
}

#[test]
fn signing_is_deterministic() {
    assert_eq!(
        signer().identity(&claims(NOW)).unwrap(),
        signer().identity(&claims(NOW)).unwrap()
    );
    let passport = signer().passport(&claims(NOW)).unwrap();
    assert!(
        signer()
            .identity(&claims(NOW))
            .unwrap()
            .starts_with(&passport)
    );
    assert_eq!(passport.split('.').count(), 3);
}

#[test]
fn the_compact_form_round_trips_from_the_request() {
    let pki = Pki::new();
    let identity = signer().identity_compact(&claims(NOW)).unwrap();
    assert!(identity.starts_with(".."));
    assert!(identity.ends_with(";alg=ES256;ppt=shaken"));
    let pending = Verifier::default()
        .start(&identity, Some(&claims(NOW)))
        .unwrap();
    let Verdict::Valid(verified) = pending.verify(&pki.chain(), &anchors(&pki), NOW) else {
        panic!("not valid");
    };
    assert_eq!(verified.attest, Some(Attest::A));

    let mut plain = claims(NOW);
    plain.shaken = None;
    let identity = signer().identity_compact(&plain).unwrap();
    // claims carrying the pair verify a plain compact form: it is left out
    let pending = Verifier::default()
        .start(&identity, Some(&claims(NOW)))
        .unwrap();
    assert_eq!(pending.claims().shaken, None);
    assert!(matches!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Valid(Verified { attest: None, .. })
    ));
}

#[test]
fn a_compact_form_is_only_as_good_as_the_claims_it_is_rebuilt_from() {
    let pki = Pki::new();
    let identity = signer().identity_compact(&claims(NOW)).unwrap();
    for changed in [
        Claims {
            orig: tn("12155551213"),
            ..claims(NOW)
        },
        Claims {
            iat: NOW - 1,
            ..claims(NOW)
        },
        Claims {
            dest: Dest::tn(tn("12125551214")),
            ..claims(NOW)
        },
        Claims {
            shaken: Some(Shaken {
                attest: Attest::B,
                origid: origid(),
            }),
            ..claims(NOW)
        },
    ] {
        let pending = Verifier::default()
            .start(&identity, Some(&changed))
            .unwrap();
        let verdict = pending.verify(&pki.chain(), &anchors(&pki), NOW);
        assert_eq!(
            verdict,
            Verdict::Invalid(Failure::BadSignature),
            "{changed:?}"
        );
    }
}

#[test]
fn a_compact_form_needs_claims() {
    let identity = signer().identity_compact(&claims(NOW)).unwrap();
    let without = Failure::Malformed(Malformed::CompactWithoutClaims);
    assert_eq!(start_failure(&identity, None), without);
    let mut plain = claims(NOW);
    plain.shaken = None;
    assert_eq!(start_failure(&identity, Some(&plain)), without);
    plain.dest = Dest::default();
    let plain_identity = signer()
        .identity_compact(&claims(NOW))
        .unwrap()
        .replace(";ppt=shaken", "");
    assert_eq!(
        start_failure(&plain_identity, Some(&plain)),
        Failure::Malformed(Malformed::Claims)
    );
}

#[test]
fn a_compact_form_with_an_unsupported_alg_or_ppt() {
    let identity = signer().identity_compact(&claims(NOW)).unwrap();
    let rs256 = identity.replace("alg=ES256", "alg=RS256");
    assert_eq!(
        start_failure(&rs256, Some(&claims(NOW))),
        Failure::UnsupportedAlgorithm
    );
    let div = identity.replace("ppt=shaken", "ppt=div");
    assert_eq!(
        start_failure(&div, Some(&claims(NOW))),
        Failure::UnsupportedPpt
    );
    // without alg, ES256 is what a compact form is rebuilt with
    let pki = Pki::new();
    let bare = identity.replace(";alg=ES256", "");
    let pending = Verifier::default()
        .start(&bare, Some(&claims(NOW)))
        .unwrap();
    assert!(matches!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Valid(_)
    ));
}

#[test]
fn stale_iat_either_way() {
    let pki = Pki::new();
    for iat in [NOW - DEFAULT_FRESHNESS, NOW + DEFAULT_FRESHNESS] {
        let identity = signer().identity(&claims(iat)).unwrap();
        assert!(matches!(
            verdict(&identity, &pki.chain(), &pki),
            Verdict::Valid(_)
        ));
    }
    for iat in [NOW - DEFAULT_FRESHNESS - 1, NOW + DEFAULT_FRESHNESS + 1, 0] {
        let identity = signer().identity(&claims(iat)).unwrap();
        let verdict = verdict(&identity, &pki.chain(), &pki);
        assert_eq!(
            verdict,
            Verdict::Invalid(Failure::Stale {
                iat,
                now: NOW,
                what: Staleness::Iat
            })
        );
        let response = verdict.sip_response().unwrap();
        assert_eq!((response.code, response.reason), (403, "Stale Date"));
        assert_eq!(verdict.verstat(), Verstat::TnValidationFailed);
    }
}

#[test]
fn the_date_is_held_to_the_window_and_to_iat() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let pending = Verifier::default().start(&identity, None).unwrap();
    let at = |date: u64| {
        pending
            .clone()
            .dated(date)
            .verify(&pki.chain(), &anchors(&pki), NOW)
    };
    for date in [NOW, NOW - DEFAULT_FRESHNESS, NOW + DEFAULT_FRESHNESS] {
        assert!(matches!(at(date), Verdict::Valid(_)), "{date}");
    }
    for date in [NOW - DEFAULT_FRESHNESS - 1, NOW + DEFAULT_FRESHNESS + 1, 0] {
        assert_eq!(
            at(date),
            Verdict::Invalid(Failure::Stale {
                iat: NOW,
                now: NOW,
                what: Staleness::Date { date }
            }),
            "{date}"
        );
    }

    // each fresh on its own, and too far from each other: signed for
    // another request's time
    let early = signer().identity(&claims(NOW - DEFAULT_FRESHNESS)).unwrap();
    let pending = Verifier::default().start(&early, None).unwrap();
    let date = NOW + 1;
    let verdict = pending
        .dated(date)
        .verify(&pki.chain(), &anchors(&pki), NOW);
    assert_eq!(
        verdict,
        Verdict::Invalid(Failure::Stale {
            iat: NOW - DEFAULT_FRESHNESS,
            now: NOW,
            what: Staleness::DateMismatch { date }
        })
    );
    let response = verdict.sip_response().unwrap();
    assert_eq!((response.code, response.reason), (403, "Stale Date"));
}

#[test]
fn a_passport_verified_once_is_refused_as_a_replay_inside_its_window() {
    let pki = Pki::new();
    let mut seen = ReplayCache::default();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let pending = Verifier::default().start(&identity, None).unwrap();
    assert!(matches!(
        pending.verify_once(&pki.chain(), &anchors(&pki), NOW, &mut seen),
        Verdict::Valid(_)
    ));
    let again = Verifier::default().start(&identity, None).unwrap();
    let verdict = again.verify_once(&pki.chain(), &anchors(&pki), NOW + 5, &mut seen);
    assert_eq!(
        verdict,
        Verdict::Invalid(Failure::Stale {
            iat: NOW,
            now: NOW + 5,
            what: Staleness::Replayed
        })
    );
    assert_eq!(verdict.verstat(), Verstat::TnValidationFailed);

    // another call signed the next second is not the same PASSporT
    let next = signer().identity(&claims(NOW + 1)).unwrap();
    let pending = Verifier::default().start(&next, None).unwrap();
    assert!(matches!(
        pending.verify_once(&pki.chain(), &anchors(&pki), NOW + 5, &mut seen),
        Verdict::Valid(_)
    ));
    assert_eq!(seen.len(), 2);

    // and what does not verify is never recorded
    let mut tampered = identity.clone();
    tampered.replace_range(
        identity.find('.').unwrap() + 1..identity.find('.').unwrap() + 2,
        "X",
    );
    if let Ok(pending) = Verifier::default().start(&tampered, None) {
        assert!(matches!(
            pending.verify_once(&pki.chain(), &anchors(&pki), NOW, &mut seen),
            Verdict::Invalid(_)
        ));
    }
    assert_eq!(seen.len(), 2);
}

#[test]
fn the_replay_cache_forgets_what_has_left_the_window_and_stays_bounded() {
    let pki = Pki::new();
    let mut seen = ReplayCache::new(2);
    for iat in [NOW - 3, NOW - 2, NOW - 1] {
        let identity = signer().identity(&claims(iat)).unwrap();
        let pending = Verifier::default().start(&identity, None).unwrap();
        assert!(matches!(
            pending.verify_once(&pki.chain(), &anchors(&pki), NOW, &mut seen),
            Verdict::Valid(_)
        ));
        assert!(seen.len() <= 2);
    }
    let later = NOW + DEFAULT_FRESHNESS;
    let identity = signer().identity(&claims(later)).unwrap();
    let pending = Verifier::default().start(&identity, None).unwrap();
    assert!(matches!(
        pending.verify_once(&pki.chain(), &anchors(&pki), later, &mut seen),
        Verdict::Valid(_)
    ));
    assert_eq!(seen.len(), 1, "what left the window went");
}

#[test]
fn info_is_fetched_over_https_unless_the_policy_names_another_scheme() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    for scheme in ["http", "file", "ldap", "data", "ftp"] {
        let elsewhere = identity.replace("https:", &format!("{scheme}:"));
        assert_eq!(
            Verifier::default().start(&elsewhere, None).err(),
            Some(Failure::BadInfo(InfoProblem::Scheme)),
            "{scheme}"
        );
    }
    // a scheme is the same scheme in either case (RFC 3986 §3.1)
    let upper = Signer::new(&[0x33; 32], "HTTPS://cert.example.org/passport.cer")
        .unwrap()
        .identity(&claims(NOW))
        .unwrap();
    assert!(Verifier::default().start(&upper, None).is_ok());

    // a deployment that fetches over plain http says so
    let http = Verifier::new(Config {
        info_schemes: &["https", "http"],
        ..Config::default()
    });
    let plain = Signer::new(&[0x33; 32], "http://cert.example.org/passport.cer")
        .unwrap()
        .identity(&claims(NOW))
        .unwrap();
    let pending = http.start(&plain, None).unwrap();
    assert!(matches!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Valid(_)
    ));
    assert_eq!(
        Verifier::default().start(&plain, None).err(),
        Some(Failure::BadInfo(InfoProblem::Scheme))
    );
}

#[test]
fn a_number_without_a_plus_goes_through_the_deployments_plan() {
    let national = |number: &str| (number.len() == 10).then(|| format!("1{number}"));
    assert_eq!(
        Tn::canonical_with("(215) 555-1212", national),
        Ok(tn("12155551212"))
    );
    // international already: the plan is not asked
    assert_eq!(
        Tn::canonical_with("+44 20 7946 0000", |_| panic!("asked")),
        Ok(tn("442079460000"))
    );
    // a plan that cannot say keeps the number as written
    assert_eq!(Tn::canonical_with("5551212", national), Ok(tn("5551212")));
    // and one that answers with something that is not a number is refused
    assert_eq!(
        Tn::canonical_with("5551212", |_| Some("not a number".to_owned())),
        Err(passport::InvalidTn)
    );
    assert_eq!(Tn::canonical("(215) 555-1212"), Ok(tn("2155551212")));
}

#[test]
fn the_freshness_window_is_configurable() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW - 300)).unwrap();
    let relaxed = Verifier::new(Config {
        freshness: 300,
        ..Config::default()
    });
    let pending = relaxed.start(&identity, None).unwrap();
    assert!(matches!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Valid(_)
    ));
    let strict = Verifier::new(Config {
        freshness: 0,
        ..Config::default()
    });
    let identity = signer().identity(&claims(NOW - 1)).unwrap();
    let pending = strict.start(&identity, None).unwrap();
    assert!(matches!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Invalid(Failure::Stale { .. })
    ));
}

#[test]
fn a_tampered_passport_does_not_verify() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let forged = CLAIMS.replace("\"A\"", "\"B\"");
    let mut parts: Vec<&str> = identity.splitn(3, '.').collect();
    let forged_segment = base64::encode_url(forged.as_bytes());
    parts[1] = &forged_segment;
    let tampered = parts.join(".");
    let verdict = verdict(&tampered, &pki.chain(), &pki);
    assert_eq!(verdict, Verdict::Invalid(Failure::BadSignature));
    assert_eq!(verdict.sip_response().unwrap().code, 438);
}

#[test]
fn a_passport_signed_by_another_key_does_not_verify() {
    let pki = Pki::new();
    let stranger = Signer::new(&[0x44; 32], X5U).unwrap();
    let identity = stranger.identity(&claims(NOW)).unwrap();
    assert_eq!(
        failure(&identity, &pki.chain(), &pki),
        Failure::BadSignature
    );
}

#[test]
fn an_out_of_range_signature_is_refused_before_the_fetch() {
    let identity = signer().identity(&claims(NOW)).unwrap();
    let (token, params) = identity.split_once(';').unwrap();
    let (signed, _) = token.rsplit_once('.').unwrap();
    let zero = base64::encode_url(&[0; 64]);
    assert_eq!(
        start_failure(&format!("{signed}.{zero};{params}"), None),
        Failure::BadSignature
    );
}

#[test]
fn a_signature_of_the_wrong_shape_is_malformed() {
    let identity = signer().identity(&claims(NOW)).unwrap();
    let (token, params) = identity.split_once(';').unwrap();
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let bytes = base64::decode_url(signature.as_bytes()).unwrap();
    let short = base64::encode_url(&bytes[..63]);
    let der = Signature::from_slice(&bytes).unwrap().to_der();
    let der = base64::encode_url(der.as_bytes());
    for signature in [short, der] {
        assert_eq!(
            start_failure(&format!("{signed}.{signature};{params}"), None),
            Failure::Malformed(Malformed::Signature)
        );
    }
    assert_eq!(
        start_failure(&format!("{signed}.AAAAA;{params}"), None),
        Failure::Malformed(Malformed::Encoding)
    );
}

#[test]
fn segments_that_are_not_base64url_json() {
    let bad_header = hand_made(HEADER, CLAIMS, "").replacen('e', "A", 1);
    assert!(matches!(
        start_failure(&bad_header, None),
        Failure::Malformed(Malformed::Json | Malformed::Encoding)
    ));
    let not_base64 = format!("eyJ.eyJ.AAAA;info=<{X5U}>");
    assert_eq!(
        start_failure(&not_base64, None),
        Failure::Malformed(Malformed::Encoding)
    );
    assert_eq!(
        start_failure(&hand_made(HEADER, "[]", ""), None),
        Failure::Malformed(Malformed::Json)
    );
    assert_eq!(
        start_failure(&hand_made(HEADER, "{\"iat\":1}", ""), None),
        Failure::Malformed(Malformed::Claims)
    );
}

#[test]
fn a_hand_made_passport_in_other_whitespace_still_verifies() {
    // the signature covers the octets as sent, not a re-serialisation
    let pki = Pki::new();
    let spaced = CLAIMS.replace(',', ", ");
    let identity = hand_made(HEADER, &spaced, ";ppt=shaken");
    assert!(matches!(
        verdict(&identity, &pki.chain(), &pki),
        Verdict::Valid(_)
    ));
}

#[test]
fn an_unsupported_algorithm() {
    let header = HEADER.replace("ES256", "RS256");
    let identity = hand_made(&header, CLAIMS, "");
    assert_eq!(
        start_failure(&identity, None),
        Failure::UnsupportedAlgorithm
    );
    assert_eq!(
        Failure::UnsupportedAlgorithm.sip_response(),
        SipResponse::UNSUPPORTED_CREDENTIAL
    );
}

#[test]
fn an_alg_parameter_that_disagrees() {
    let identity = hand_made(HEADER, CLAIMS, ";alg=RS256");
    assert_eq!(
        start_failure(&identity, None),
        Failure::Malformed(Malformed::AlgMismatch)
    );
}

#[test]
fn an_unsupported_ppt() {
    let header = HEADER.replace("shaken", "div");
    let identity = hand_made(&header, CLAIMS, ";ppt=div");
    assert_eq!(start_failure(&identity, None), Failure::UnsupportedPpt);
    assert_eq!(
        Verdict::Invalid(Failure::UnsupportedPpt).verstat(),
        Verstat::NoTnValidation
    );
}

#[test]
fn a_ppt_parameter_that_disagrees() {
    let plain = HEADER.replace(r#""ppt":"shaken","#, "");
    let identity = hand_made(&plain, CLAIMS, ";ppt=shaken");
    assert_eq!(
        start_failure(&identity, None),
        Failure::Malformed(Malformed::PptMismatch)
    );
    // a ppt this verifier does not support is RFC 8224 §6.2's Step 1, taken
    // before the PASSporT is read: the header field is ignored, not broken
    let identity = hand_made(HEADER, CLAIMS, ";ppt=div");
    assert_eq!(start_failure(&identity, None), Failure::UnsupportedPpt);
    assert_eq!(
        Failure::UnsupportedPpt.sip_response(),
        SipResponse::USE_SUPPORTED_PASSPORT_FORMAT
    );
    // left out, it disagrees with nothing
    let pki = Pki::new();
    let identity = hand_made(HEADER, CLAIMS, "");
    assert!(matches!(
        verdict(&identity, &pki.chain(), &pki),
        Verdict::Valid(_)
    ));
}

#[test]
fn x5u_and_info_must_agree() {
    let identity = hand_made(HEADER, CLAIMS, "").replace(
        "info=<https://cert.example.org/passport.cer>",
        "info=<https://elsewhere.example.org/passport.cer>",
    );
    assert_eq!(
        start_failure(&identity, None),
        Failure::BadInfo(InfoProblem::Mismatch)
    );
    // a plain header without x5u takes the certificate from info alone
    let pki = Pki::new();
    let bare = r#"{"alg":"ES256","typ":"passport"}"#;
    let identity = hand_made(bare, CLAIMS, "");
    assert!(matches!(
        verdict(&identity, &pki.chain(), &pki),
        Verdict::Valid(_)
    ));
}

#[test]
fn a_shaken_passport_names_its_certificate_in_x5u() {
    // without x5u, nothing signed says which certificate the signer meant,
    // and info could be pointed at any other certificate for the same key
    let bare = HEADER.replace(r#","x5u":"https://cert.example.org/passport.cer""#, "");
    for params in ["", ";ppt=shaken"] {
        assert_eq!(
            start_failure(&hand_made(&bare, CLAIMS, params), None),
            Failure::Malformed(Malformed::Header),
            "{params}"
        );
    }
    let null = HEADER.replace(r#""https://cert.example.org/passport.cer""#, "null");
    assert_eq!(
        start_failure(&hand_made(&null, CLAIMS, ""), None),
        Failure::Malformed(Malformed::Header)
    );
}

#[test]
fn a_certificate_that_cannot_be_fetched() {
    let identity = signer().identity(&claims(NOW)).unwrap();
    let pending = Verifier::default().start(&identity, None).unwrap();
    let verdict = pending.unavailable();
    assert_eq!(
        verdict,
        Verdict::Invalid(Failure::BadInfo(InfoProblem::Unavailable))
    );
    assert_eq!(verdict.sip_response(), Some(SipResponse::BAD_IDENTITY_INFO));
}

#[test]
fn a_certificate_that_cannot_be_read() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    assert_eq!(
        failure(&identity, b"<html>not found</html>", &pki),
        Failure::BadInfo(InfoProblem::Empty)
    );
    assert_eq!(
        failure(&identity, &[0x30, 0x03, 0x02, 0x01, 0x00], &pki),
        Failure::BadInfo(InfoProblem::Unreadable)
    );
    assert_eq!(
        failure(&identity, &pki.leaf.repeat(11), &pki),
        Failure::BadInfo(InfoProblem::TooManyCertificates)
    );
    assert_eq!(
        failure(&identity, &vec![b' '; MAX_CHAIN_LEN + 1], &pki),
        Failure::BadInfo(InfoProblem::TooLarge)
    );
}

#[test]
fn a_chain_to_no_trust_anchor() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let pending = Verifier::default().start(&identity, None).unwrap();
    let verdict = pending.verify(&pki.chain(), &TrustAnchors::new(), NOW);
    assert_eq!(verdict, Verdict::Invalid(Failure::Untrusted));
    assert_eq!(
        verdict.sip_response(),
        Some(SipResponse::UNSUPPORTED_CREDENTIAL)
    );

    // a root of another name, and a root of the same name with another key
    let mut other = pki.root_spec();
    other.subject = "Another Root";
    other.issuer = "Another Root";
    let mut anchors = TrustAnchors::new();
    anchors.add(&other.build(&pki.root_key)).unwrap();
    assert_eq!(
        pending.verify(&pki.chain(), &anchors, NOW),
        Verdict::Invalid(Failure::Untrusted)
    );
    let mut impostor = pki.root_spec();
    impostor.public_key = testpki::point(&testpki::key(0x55));
    let mut anchors = TrustAnchors::new();
    anchors.add(&impostor.build(&testpki::key(0x55))).unwrap();
    assert_eq!(
        pending.verify(&pki.chain(), &anchors, NOW),
        Verdict::Invalid(Failure::InvalidChain(ChainProblem::Signature { depth: 1 }))
    );
    // the intermediate left out of the chain
    assert_eq!(
        pending.verify(&pki.leaf, &crate::tests::anchors(&pki), NOW),
        Verdict::Invalid(Failure::Untrusted)
    );
}

#[test]
fn a_self_signed_root_in_the_chain_is_not_an_anchor() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let pending = Verifier::default().start(&identity, None).unwrap();
    let chain = [pki.chain(), pki.root.clone()].concat();
    let mut elsewhere = TrustAnchors::new();
    let mut other = pki.root_spec();
    other.subject = "Another Root";
    other.issuer = "Another Root";
    elsewhere.add(&other.build(&pki.root_key)).unwrap();
    assert_eq!(
        pending.verify(&chain, &elsewhere, NOW),
        Verdict::Invalid(Failure::Untrusted)
    );
}

#[test]
fn validity_periods() {
    let pki = Pki::new();
    let identity = |at| signer().identity(&claims(at)).unwrap();
    let at = |now: u64| {
        let pending = Verifier::default().start(&identity(now), None).unwrap();
        pending.verify(&pki.chain(), &anchors(&pki), now)
    };
    assert!(matches!(at(NOT_BEFORE), Verdict::Valid(_)));
    assert!(matches!(at(NOT_AFTER), Verdict::Valid(_)));
    assert_eq!(
        at(NOT_BEFORE - 1),
        Verdict::Invalid(Failure::NotYetValid { depth: 0 })
    );
    assert_eq!(
        at(NOT_AFTER + 1),
        Verdict::Invalid(Failure::Expired { depth: 0 })
    );

    let mut leaf = pki.leaf_spec();
    leaf.not_after = NOW - 1;
    let expired = verdict(&identity(NOW), &chain_with_leaf(&pki, &leaf), &pki);
    assert_eq!(expired, Verdict::Invalid(Failure::Expired { depth: 0 }));
    assert_eq!(expired.sip_response().unwrap().code, 437);

    let mut intermediate = pki.intermediate_spec();
    intermediate.not_after = NOW - 1;
    assert_eq!(
        failure(
            &identity(NOW),
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::Expired { depth: 1 }
    );
    intermediate.not_after = NOT_AFTER;
    intermediate.not_before = NOW + 1;
    assert_eq!(
        failure(
            &identity(NOW),
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::NotYetValid { depth: 1 }
    );
    // GeneralizedTime, after 2049, reads the same way
    let mut long_lived = pki.leaf_spec();
    long_lived.not_after = 2_600_000_000;
    assert!(matches!(
        verdict(&identity(NOW), &chain_with_leaf(&pki, &long_lived), &pki),
        Verdict::Valid(_)
    ));
}

#[test]
fn an_issuer_must_be_a_ca() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let mut intermediate = pki.intermediate_spec();
    intermediate.basic = None;
    assert_eq!(
        failure(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::InvalidChain(ChainProblem::NotCa { depth: 1 })
    );
    intermediate.basic = Some((false, None));
    assert_eq!(
        failure(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::InvalidChain(ChainProblem::NotCa { depth: 1 })
    );
}

#[test]
fn an_issuer_must_be_allowed_to_sign_certificates() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let mut intermediate = pki.intermediate_spec();
    intermediate.key_usage = Some(DIGITAL_SIGNATURE);
    assert_eq!(
        failure(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::InvalidChain(ChainProblem::KeyUsage { depth: 1 })
    );
    // without the extension, nothing is restricted
    intermediate.key_usage = None;
    assert!(matches!(
        verdict(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Verdict::Valid(_)
    ));
}

#[test]
fn the_signer_must_be_allowed_to_sign() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let mut leaf = pki.leaf_spec();
    leaf.key_usage = Some(KEY_CERT_SIGN);
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::InvalidChain(ChainProblem::KeyUsage { depth: 0 })
    );
    leaf.key_usage = None;
    assert!(matches!(
        verdict(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Verdict::Valid(_)
    ));
}

#[test]
fn path_length_constraints() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    // root → upper (pathLen 0) → intermediate → signer: one CA below upper
    let upper_key = testpki::key(0x66);
    let mut upper = pki.root_spec();
    upper.subject = "Sipral Test STI Upper";
    upper.issuer = testpki::ROOT;
    upper.public_key = testpki::point(&upper_key);
    upper.basic = Some((true, Some(0)));
    let upper_der = upper.build(&pki.root_key);
    let mut intermediate = pki.intermediate_spec();
    intermediate.issuer = "Sipral Test STI Upper";
    intermediate.basic = Some((true, None));
    let intermediate_der = intermediate.build(&upper_key);
    let chain = [pki.leaf.clone(), intermediate_der.clone(), upper_der].concat();
    assert_eq!(
        failure(&identity, &chain, &pki),
        Failure::InvalidChain(ChainProblem::PathLength { depth: 2 })
    );
    upper.basic = Some((true, Some(1)));
    let chain = [
        pki.leaf.clone(),
        intermediate_der,
        upper.build(&pki.root_key),
    ]
    .concat();
    assert!(matches!(
        verdict(&identity, &chain, &pki),
        Verdict::Valid(_)
    ));
}

#[test]
fn unknown_critical_extensions_are_refused_and_others_ignored() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let mut leaf = pki.leaf_spec();
    leaf.extra
        .push(("1.3.6.1.4.1.99999.1", false, vec![0x05, 0x00]));
    assert!(matches!(
        verdict(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Verdict::Valid(_)
    ));
    leaf.extra = vec![("1.3.6.1.4.1.99999.1", true, vec![0x05, 0x00])];
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::InvalidChain(ChainProblem::CriticalExtension { depth: 0 })
    );
    let mut intermediate = pki.intermediate_spec();
    intermediate.extra = vec![("1.3.6.1.4.1.99999.1", true, vec![0x05, 0x00])];
    assert_eq!(
        failure(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::InvalidChain(ChainProblem::CriticalExtension { depth: 1 })
    );
}

#[test]
fn an_extension_twice_is_refused() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let mut leaf = pki.leaf_spec();
    let list = leaf.tn_auth_list.clone().unwrap();
    leaf.extra.push((tnauthlist::OID, false, list));
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::InvalidChain(ChainProblem::DuplicateExtension { depth: 0 })
    );
}

#[test]
fn unreadable_extensions() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let mut leaf = pki.leaf_spec();
    leaf.tn_auth_list = Some(vec![0x30, 0x00]);
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::InvalidChain(ChainProblem::BadExtension { depth: 0 })
    );
    let mut intermediate = pki.intermediate_spec();
    intermediate.basic = None;
    intermediate.extra = vec![("2.5.29.19", true, vec![0x04, 0x00])];
    assert_eq!(
        failure(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::InvalidChain(ChainProblem::BadExtension { depth: 1 })
    );
    let mut intermediate = pki.intermediate_spec();
    intermediate.key_usage = None;
    intermediate.extra = vec![("2.5.29.15", true, vec![0x04, 0x00])];
    assert_eq!(
        failure(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::InvalidChain(ChainProblem::BadExtension { depth: 1 })
    );
}

#[test]
fn unsupported_certificate_algorithms() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    // the two signature algorithm fields disagree
    let mut leaf = pki.leaf_spec();
    leaf.outer_algorithm = Some(ECDSA_WITH_SHA384);
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::InvalidChain(ChainProblem::Algorithm { depth: 0 })
    );
    // the outer one is right and the one the signature covers is not
    let mut leaf = pki.leaf_spec();
    leaf.algorithm = ECDSA_WITH_SHA384;
    leaf.outer_algorithm = Some(testpki::ECDSA_WITH_SHA256);
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::InvalidChain(ChainProblem::Algorithm { depth: 0 })
    );
    // parameters, which ECDSA's identifiers never carry
    let mut leaf = pki.leaf_spec();
    leaf.null_parameters = true;
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::InvalidChain(ChainProblem::Algorithm { depth: 0 })
    );
    // they agree, on an algorithm other than ECDSA with SHA-256
    let mut intermediate = pki.intermediate_spec();
    intermediate.algorithm = ECDSA_WITH_SHA384;
    assert_eq!(
        failure(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::InvalidChain(ChainProblem::Algorithm { depth: 1 })
    );
}

#[test]
fn a_signing_certificate_without_a_p256_key() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let mut leaf = pki.leaf_spec();
    leaf.curve = "1.3.132.0.34";
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::InvalidChain(ChainProblem::Algorithm { depth: 0 })
    );
    // and an issuer without one cannot have signed it
    let mut intermediate = pki.intermediate_spec();
    intermediate.curve = "1.3.132.0.34";
    assert_eq!(
        failure(
            &identity,
            &chain_with_intermediate(&pki, &intermediate),
            &pki
        ),
        Failure::InvalidChain(ChainProblem::Algorithm { depth: 1 })
    );
}

#[test]
fn a_certificate_signed_by_the_wrong_key() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    // it names the intermediate as issuer, but the root signed it
    let chain = [
        pki.leaf_spec().build(&pki.root_key),
        pki.intermediate.clone(),
    ]
    .concat();
    assert_eq!(
        failure(&identity, &chain, &pki),
        Failure::InvalidChain(ChainProblem::Signature { depth: 0 })
    );
}

#[test]
fn the_originating_number_must_be_covered() {
    let pki = Pki::new();
    let mut other = claims(NOW);
    other.orig = tn("12155559999");
    let identity = signer().identity(&other).unwrap();
    let verdict = verdict(&identity, &pki.chain(), &pki);
    assert_eq!(verdict, Verdict::Invalid(Failure::TnNotCovered));
    assert_eq!(
        verdict.sip_response(),
        Some(SipResponse::INVALID_IDENTITY_HEADER)
    );
    assert_eq!(verdict.verstat(), Verstat::TnValidationFailed);

    // no TNAuthList at all
    let identity = signer().identity(&claims(NOW)).unwrap();
    let mut leaf = pki.leaf_spec();
    leaf.tn_auth_list = None;
    assert_eq!(
        failure(&identity, &chain_with_leaf(&pki, &leaf), &pki),
        Failure::TnNotCovered
    );
}

#[test]
fn coverage_by_range() {
    let pki = Pki::new();
    let mut leaf = pki.leaf_spec();
    leaf.tn_auth_list = Some(
        TnAuthList::new(vec![TnEntry::Range {
            start: "12155551200".to_owned(),
            count: 100,
        }])
        .unwrap()
        .to_der(),
    );
    let chain = chain_with_leaf(&pki, &leaf);
    let identity = signer().identity(&claims(NOW)).unwrap();
    let Verdict::Valid(verified) = verdict(&identity, &chain, &pki) else {
        panic!("not valid");
    };
    assert_eq!(verified.coverage, Coverage::Range);
    let mut outside = claims(NOW);
    outside.orig = tn("12155551300");
    let identity = signer().identity(&outside).unwrap();
    assert_eq!(failure(&identity, &chain, &pki), Failure::TnNotCovered);
}

#[test]
fn coverage_by_service_provider_code_is_policy() {
    let pki = Pki::new();
    let mut leaf = pki.leaf_spec();
    leaf.tn_auth_list = Some(
        TnAuthList::new(vec![TnEntry::Spc("709J".to_owned())])
            .unwrap()
            .to_der(),
    );
    let chain = chain_with_leaf(&pki, &leaf);
    let identity = signer().identity(&claims(NOW)).unwrap();

    // by default a code covers no number: only the application knows
    // whether the provider it names may vouch for this one
    assert!(!Config::default().accept_service_provider_codes);
    assert_eq!(
        verdict(&identity, &chain, &pki),
        Verdict::Invalid(Failure::TnNotCovered)
    );

    let providers = Verifier::new(Config {
        accept_service_provider_codes: true,
        ..Config::default()
    });
    let pending = providers.start(&identity, None).unwrap();
    let Verdict::Valid(verified) = pending.verify(&chain, &anchors(&pki), NOW) else {
        panic!("not valid");
    };
    assert_eq!(
        verified.coverage,
        Coverage::ServiceProvider("709J".to_owned())
    );
}

#[test]
fn signer_errors() {
    assert_eq!(
        Signer::new(&[0; 32], X5U).unwrap_err(),
        SignError::InvalidKey
    );
    assert_eq!(
        Signer::new(&[0xff; 32], X5U).unwrap_err(),
        SignError::InvalidKey
    );
    assert_eq!(
        Signer::new(&[0x33; 32], "cert.example.org/passport.cer").unwrap_err(),
        SignError::InvalidUri
    );
    let mut nowhere = claims(NOW);
    nowhere.dest = Dest::default();
    assert_eq!(signer().identity(&nowhere), Err(SignError::EmptyDest));
    assert_eq!(signer().passport(&nowhere), Err(SignError::EmptyDest));
    let mut long = claims(NOW);
    long.dest
        .uri
        .push(format!("sip:{}@example.com", "a".repeat(MAX_IDENTITY_LEN)));
    assert_eq!(signer().identity(&long), Err(SignError::TooLong));
    assert_eq!(signer().identity_compact(&long).map(|_| ()), Ok(()));
    assert!(format!("{:?}", signer()).starts_with("Signer { x5u: "));
    assert_eq!(SignError::EmptyDest.to_string(), "no destination");
}

#[test]
fn the_public_key_is_what_the_certificate_holds() {
    let pki = Pki::new();
    assert_eq!(signer().public_key(), testpki::point(&pki.leaf_key));
    assert_eq!(signer().public_key().len(), 65);
}

/// A deterministic stream of octets, for mutating inputs.
struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }
}

#[test]
fn mangled_header_fields_never_panic() {
    let pki = Pki::new();
    let anchors = anchors(&pki);
    let chain = pki.chain();
    let full = signer().identity(&claims(NOW)).unwrap();
    let compact = signer().identity_compact(&claims(NOW)).unwrap();
    let mut random = Lcg(7);
    for original in [full, compact] {
        let bytes = original.as_bytes();
        for cut in 0..bytes.len() {
            let text = String::from_utf8_lossy(&bytes[..cut]);
            if let Ok(pending) = Verifier::default().start(&text, Some(&claims(NOW))) {
                let _ = pending.verify(&chain, &anchors, NOW);
            }
        }
        for _ in 0..2000 {
            let mut mutated = bytes.to_vec();
            for _ in 0..=random.next() % 4 {
                let at = usize::try_from(random.next()).unwrap() % mutated.len();
                mutated[at] = u8::try_from(random.next() % 256).unwrap();
            }
            let text = String::from_utf8_lossy(&mutated);
            if let Ok(pending) = Verifier::default().start(&text, Some(&claims(NOW))) {
                let _ = pending.verify(&chain, &anchors, NOW);
            }
        }
    }
}

#[test]
fn mangled_chains_never_panic() {
    let pki = Pki::new();
    let anchors = anchors(&pki);
    let identity = signer().identity(&claims(NOW)).unwrap();
    let pending = Verifier::default().start(&identity, None).unwrap();
    let chain = pki.chain();
    let text = format!("{}{}", pem(&pki.leaf), pem(&pki.intermediate));
    let mut random = Lcg(11);
    for original in [chain, text.into_bytes()] {
        for cut in (0..original.len()).step_by(7) {
            let _ = pending.verify(&original[..cut], &anchors, NOW);
        }
        for _ in 0..1000 {
            let mut mutated = original.clone();
            for _ in 0..=random.next() % 3 {
                let at = usize::try_from(random.next()).unwrap() % mutated.len();
                mutated[at] = u8::try_from(random.next() % 256).unwrap();
            }
            let _ = pending.verify(&mutated, &anchors, NOW);
            let _ = TrustAnchors::new().add(&mutated);
            let _ = TnAuthList::from_der(&mutated);
        }
    }
}

/// A PASSporT of these JSON texts carrying `signature`, whatever it is, as
/// its third segment.
fn with_signature(header: &str, claims: &str, signature: &str) -> String {
    let header = base64::encode_url(header.as_bytes());
    let claims = base64::encode_url(claims.as_bytes());
    format!("{header}.{claims}.{signature};info=<{X5U}>")
}

fn start(identity: &str) -> Pending {
    Verifier::default().start(identity, None).unwrap()
}

#[test]
fn no_algorithm_but_es256_is_verified() {
    for alg in [
        "none", "HS256", "es256", "Es256", "ES256 ", "ES384", "RS256", "",
    ] {
        let header = HEADER.replace(r#""alg":"ES256""#, &format!(r#""alg":"{alg}""#));
        // no signature at all is not even the grammar of the header field
        assert_eq!(
            start_failure(&with_signature(&header, CLAIMS, ""), None),
            Failure::Malformed(Malformed::Syntax),
            "{alg}"
        );
        // and a good ES256 signature does not make up for another alg
        assert_eq!(
            start_failure(&hand_made(&header, CLAIMS, ""), None),
            Failure::UnsupportedAlgorithm,
            "{alg}"
        );
    }
    for header in [
        HEADER.replace(r#""alg":"ES256","#, ""),
        HEADER.replace(r#""alg":"ES256""#, r#""alg":null"#),
        HEADER.replace(r#""alg":"ES256""#, r#""alg":["ES256"]"#),
        HEADER.replace(r#""typ":"passport""#, r#""typ":"PASSporT""#),
        HEADER.replace(r#""typ":"passport""#, r#""typ":"JWT""#),
        HEADER.replace(r#""typ":"passport","#, ""),
    ] {
        assert_eq!(
            start_failure(&hand_made(&header, CLAIMS, ""), None),
            Failure::Malformed(Malformed::Header),
            "{header}"
        );
    }
}

#[test]
fn a_header_parameter_twice_is_refused_whichever_comes_last() {
    for header in [
        HEADER.replace(r#""alg":"ES256","#, r#""alg":"ES256","alg":"none","#),
        HEADER.replace(r#""alg":"ES256","#, r#""alg":"none","alg":"ES256","#),
        HEADER.replace(r#""alg":"ES256","#, r#""alg":"ES256","al\u0067":"none","#),
        HEADER.replace(r#""ppt":"shaken","#, r#""ppt":"shaken","ppt":"div","#),
        HEADER.replace(r#""typ":"passport","#, r#""typ":"passport","typ":"JWT","#),
    ] {
        assert_eq!(
            start_failure(&hand_made(&header, CLAIMS, ""), None),
            Failure::Malformed(Malformed::Json),
            "{header}"
        );
    }
    let claims = CLAIMS.replace(r#""iat":1790000000,"#, r#""iat":1790000000,"iat":0,"#);
    assert_eq!(
        start_failure(&hand_made(HEADER, &claims, ""), None),
        Failure::Malformed(Malformed::Json)
    );
}

#[test]
fn a_critical_header_parameter_is_refused() {
    for crit in ["[]", r#"["ppt"]"#, r#"["x"]"#, "null"] {
        let header = HEADER.replace(
            r#""alg":"ES256","#,
            &format!(r#""alg":"ES256","crit":{crit},"#),
        );
        assert_eq!(
            start_failure(&hand_made(&header, CLAIMS, ""), None),
            Failure::Malformed(Malformed::Critical),
            "{crit}"
        );
    }
}

/// `a - b` for 32-octet big-endian integers, `a` the larger.
fn minus(a: &[u8], b: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut digit = i16::from(a[i]) - i16::from(b[i]) - borrow;
        borrow = i16::from(digit < 0);
        if digit < 0 {
            digit += 256;
        }
        out[i] = u8::try_from(digit).unwrap();
    }
    out
}

/// The order of the P-256 group.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

#[test]
fn es256_signatures_are_r_and_s_in_range_and_nothing_else() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let (token, params) = identity.split_once(';').unwrap();
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let bytes = base64::decode_url(signature.as_bytes()).unwrap();
    let (r, s) = bytes.split_at(32);
    let with = |signature: &[u8]| format!("{signed}.{};{params}", base64::encode_url(signature));

    // the wrong length, whatever it holds
    let long = [&bytes[..], &[0]].concat();
    let padded = [&[0][..], &bytes[..]].concat();
    let der = Signature::from_slice(&bytes).unwrap().to_der();
    for wrong in [
        &bytes[..63],
        &long[..],
        &padded[..],
        &bytes[..32],
        der.as_bytes(),
        &[0],
    ] {
        assert_eq!(
            start_failure(&with(wrong), None),
            Failure::Malformed(Malformed::Signature),
            "{}",
            wrong.len()
        );
    }
    // zero, or not below the group order
    let zero = [0u8; 32];
    for (r, s) in [
        (&zero[..], s),
        (r, &zero[..]),
        (&ORDER[..], s),
        (r, &ORDER[..]),
        (&[0xff; 32][..], s),
        (r, &[0xff; 32][..]),
    ] {
        assert_eq!(
            start_failure(&with(&[r, s].concat()), None),
            Failure::BadSignature
        );
    }
    // r and s swapped
    let swapped = start(&with(&[s, r].concat()));
    assert_eq!(
        swapped.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Invalid(Failure::BadSignature)
    );
    // RFC 7518 §3.4 does not ask for a low s: n - s verifies as s does
    let other_s = minus(&ORDER, s);
    let flipped = start(&with(&[r, &other_s[..]].concat()));
    assert!(matches!(
        flipped.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Valid(_)
    ));
    // a stray bit after the last octet is not another spelling of it
    let stray = match signature.chars().last().unwrap() {
        'A' => 'B',
        'Q' => 'R',
        'g' => 'h',
        'w' => 'x',
        other => panic!("{other} carries data in its low bits"),
    };
    let respelled = format!(
        "{signed}.{}{stray};{params}",
        &signature[..signature.len() - 1]
    );
    assert_eq!(
        start_failure(&respelled, None),
        Failure::Malformed(Malformed::Encoding)
    );
}

#[test]
fn a_signature_is_only_good_for_the_octets_it_was_made_over() {
    let pki = Pki::new();
    let identity = signer().identity(&claims(NOW)).unwrap();
    let (token, params) = identity.split_once(';').unwrap();
    let mut segments = token.split('.');
    let (header, payload, signature) = (
        segments.next().unwrap(),
        segments.next().unwrap(),
        segments.next().unwrap(),
    );
    // the same JSON in other whitespace, or with an escape, is other octets
    let decoded = String::from_utf8(base64::decode_url(payload.as_bytes()).unwrap()).unwrap();
    for respelled in [
        decoded.replace(',', ", "),
        format!(" {decoded}"),
        decoded.replace("\"A\"", "\"\\u0041\""),
    ] {
        let respelled = base64::encode_url(respelled.as_bytes());
        let pending = start(&format!("{header}.{respelled}.{signature};{params}"));
        assert_eq!(
            pending.verify(&pki.chain(), &anchors(&pki), NOW),
            Verdict::Invalid(Failure::BadSignature)
        );
    }
    // the full form's signature is no compact form's for other claims
    let compact = format!("..{signature};{params}");
    let mut other = claims(NOW);
    other.orig = tn("12155551213");
    let pending = Verifier::default().start(&compact, Some(&other)).unwrap();
    assert_eq!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Invalid(Failure::BadSignature)
    );
    // and for the same claims it is: the compact form is rebuilt in the
    // deterministic form the full one was signed in
    let pending = Verifier::default()
        .start(&compact, Some(&claims(NOW)))
        .unwrap();
    assert!(matches!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Valid(_)
    ));
}

#[test]
fn iat_values_that_are_not_seconds_are_refused() {
    let huge = "9".repeat(4000);
    for iat in [
        "18446744073709551616",
        huge.as_str(),
        "-1",
        "-0",
        "1790000000.0",
        "1.79e9",
        "1790000000e0",
        "1E9",
        r#""1790000000""#,
        "null",
        "true",
        "[1790000000]",
        "{}",
    ] {
        let claims = CLAIMS.replace("1790000000", iat);
        assert_eq!(
            start_failure(&hand_made(HEADER, &claims, ""), None),
            Failure::Malformed(Malformed::Claims),
            "{iat}"
        );
    }
    for iat in ["01790000000", "+1790000000", "0x6AB0B680", "1790000000."] {
        let claims = CLAIMS.replace("1790000000", iat);
        assert_eq!(
            start_failure(&hand_made(HEADER, &claims, ""), None),
            Failure::Malformed(Malformed::Json),
            "{iat}"
        );
    }
}

#[test]
fn iat_at_the_ends_of_the_clock() {
    let pki = Pki::new();
    let max = CLAIMS.replace("1790000000", &u64::MAX.to_string());
    let pending = start(&hand_made(HEADER, &max, ""));
    for now in [NOW, 0] {
        assert_eq!(
            pending.verify(&pki.chain(), &anchors(&pki), now),
            Verdict::Invalid(Failure::Stale {
                iat: u64::MAX,
                now,
                what: Staleness::Iat
            })
        );
    }
    let zero = CLAIMS.replace("1790000000", "0");
    let pending = start(&hand_made(HEADER, &zero, ""));
    assert_eq!(
        pending.verify(&pki.chain(), &anchors(&pki), u64::MAX),
        Verdict::Invalid(Failure::Stale {
            iat: 0,
            now: u64::MAX,
            what: Staleness::Iat
        })
    );
    // a window as wide as the clock lets anything through the freshness
    // check, and nothing through the others it would not otherwise pass
    let open = Verifier::new(Config {
        freshness: u64::MAX,
        ..Config::default()
    });
    let pending = open.start(&hand_made(HEADER, &zero, ""), None).unwrap();
    assert!(matches!(
        pending.verify(&pki.chain(), &anchors(&pki), NOW),
        Verdict::Valid(_)
    ));
    assert_eq!(
        pending.verify(&pki.chain(), &anchors(&pki), u64::MAX),
        Verdict::Invalid(Failure::Expired { depth: 0 })
    );
}

#[test]
fn certificates_that_issue_each_other_lead_nowhere() {
    let pki = Pki::new();
    let pending = start(&signer().identity(&claims(NOW)).unwrap());
    // the intermediate issued by "Loop", and "Loop" by the intermediate
    let loop_key = testpki::key(0x77);
    let mut intermediate = pki.intermediate_spec();
    intermediate.issuer = "Loop";
    let intermediate = intermediate.build(&loop_key);
    let mut looping = pki.root_spec();
    looping.subject = "Loop";
    looping.issuer = testpki::INTERMEDIATE;
    looping.public_key = testpki::point(&loop_key);
    let looping = looping.build(&pki.intermediate_key);
    let chain = [pki.leaf.clone(), intermediate.clone(), looping.clone()].concat();
    assert_eq!(
        pending.verify(&chain, &anchors(&pki), NOW),
        Verdict::Invalid(Failure::Untrusted)
    );
    // as many copies as a chain may hold change nothing
    let mut copies = pki.leaf.clone();
    for _ in 0..(MAX_CHAIN_CERTIFICATES - 1) / 2 {
        copies.extend(&intermediate);
        copies.extend(&looping);
    }
    assert_eq!(
        pending.verify(&copies, &anchors(&pki), NOW),
        Verdict::Invalid(Failure::Untrusted)
    );
    // and a real intermediate twice is still a good chain
    let twice = [pki.chain(), pki.intermediate.clone()].concat();
    assert!(matches!(
        pending.verify(&twice, &anchors(&pki), NOW),
        Verdict::Valid(_)
    ));
}

#[test]
fn a_root_of_the_anchors_name_and_another_key_is_not_the_anchor() {
    let pki = Pki::new();
    let pending = start(&signer().identity(&claims(NOW)).unwrap());
    // an attacker's root, named as the real one is, and its own intermediate
    let rogue_key = testpki::key(0x55);
    let mut rogue = pki.root_spec();
    rogue.public_key = testpki::point(&rogue_key);
    let rogue = rogue.build(&rogue_key);
    let intermediate = pki.intermediate_spec().build(&rogue_key);
    let chain = [pki.leaf.clone(), intermediate, rogue].concat();
    assert!(matches!(
        pending.verify(&chain, &anchors(&pki), NOW),
        Verdict::Invalid(Failure::InvalidChain(ChainProblem::Signature { .. }))
    ));
}
