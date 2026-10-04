// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A PBX's self-signed certificate, pinned per account, against certificates
//! minted for each test and never kept.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Account, CertificatePin, PinMismatch, TransportId, Uri};

/// A self-signed certificate for `name`, valid between the two years, in DER.
fn self_signed(name: &str, from: i32, until: i32) -> Vec<u8> {
    let mut params = rcgen::CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.not_before = rcgen::date_time_ymd(from, 1, 1);
    params.not_after = rcgen::date_time_ymd(until, 1, 1);
    let key = rcgen::KeyPair::generate().unwrap();
    params.self_signed(&key).unwrap().der().to_vec()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn account() -> Account {
    Account::new(
        Uri::parse_str("sip:alice@pbx.example.com").unwrap(),
        Uri::parse_str("sips:pbx.example.com").unwrap(),
        Uri::parse_str("sips:alice@192.0.2.1").unwrap(),
        TransportId(3),
        "192.0.2.9:5061".parse::<SocketAddr>().unwrap(),
    )
}

#[test]
fn the_pinned_certificate_is_trusted_whatever_name_it_carries() {
    // the certificate a PBX mints for itself names `localhost`, not the
    // address the phones use: the pin is what is trusted, not the name
    let pbx = self_signed("localhost", 2024, 2099);
    let copied = CertificatePin::of(&pbx).to_string();
    let pin = CertificatePin::parse(&copied).unwrap();
    let account = account().tls_pin(pin);
    let held = account.pinned_certificate().copied().expect("the pin");
    let verdict = held.check(&pbx, now()).expect("the pinned certificate");
    assert!(!verdict.expired && !verdict.not_yet_valid);
    assert!(verdict.not_after.is_some());
    assert_eq!(held.sha256(), pin.sha256());
}

#[test]
fn any_other_certificate_is_refused_even_for_the_same_name_and_dates() {
    // a man in the middle mints his own for the same name
    let pbx = self_signed("pbx.example.com", 2024, 2099);
    let impostor = self_signed("pbx.example.com", 2024, 2099);
    let pin = CertificatePin::of(&pbx);
    assert_eq!(pin.check(&impostor, now()), Err(PinMismatch));
    assert!(!pin.matches(&impostor));
    assert!(
        !pin.matches(&[]),
        "nothing presented is not the pinned certificate"
    );
}

#[test]
fn an_expired_pinned_certificate_is_accepted_and_reported_expired() {
    // decided: the pin is the trust decision, and a PBX whose self-signed
    // certificate lapsed keeps working, with the lapse said out loud
    let lapsed = self_signed("pbx.example.com", 2019, 2020);
    let verdict = CertificatePin::of(&lapsed)
        .check(&lapsed, now())
        .expect("accepted by its pin");
    assert!(verdict.expired);
    assert!(verdict.not_after.is_some_and(|until| until < now()));

    let early = self_signed("pbx.example.com", 2090, 2099);
    let verdict = CertificatePin::of(&early).check(&early, now()).unwrap();
    assert!(verdict.not_yet_valid && !verdict.expired);
}

#[test]
fn an_account_without_a_pin_has_none() {
    assert!(account().pinned_certificate().is_none());
}
