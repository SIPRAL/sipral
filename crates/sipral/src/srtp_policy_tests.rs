// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! SRTP policy per account, the suites an account allows and orders, the
//! calls a policy refuses, and the encryption report — two stacks calling
//! each other with no network under either, as in `crate::tests`.

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, parse as parse_message};
use sipral_rtp::srtp::Suite;

use crate::capabilities::SrtpKeying;
use crate::codec::CodecCatalog;
use crate::error::MediaError;
use crate::event::{Event, MediaEvent};
use crate::keying::{AccountSrtp, SrtpPolicy};
use crate::tests::{Pair, callee_media, callee_sip, caller_media, one_stream, uri};
use crate::{OutgoingCall, StreamEncryption, TransportId, UaEvent};

const UDP: TransportId = TransportId(1);

fn pcmu() -> CodecCatalog {
    CodecCatalog::with_order(&["PCMU"]).expect("an order")
}

fn report(pair: &Pair, call: sipral_ua::CallHandle, caller: bool) -> StreamEncryption {
    let stack = if caller { &pair.caller } else { &pair.callee };
    let report = stack.engine.encryption(call).expect("a session");
    assert_eq!(report.len(), 1, "one stream: {report:?}");
    report[0]
}

/// The status line of every response a side sent.
fn statuses(sent: &[Vec<u8>]) -> Vec<String> {
    sent.iter()
        .filter(|bytes| bytes.starts_with(b"SIP/2.0 "))
        .map(|bytes| {
            String::from_utf8_lossy(bytes)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .collect()
}

#[test]
fn an_sdes_call_reports_its_suite_and_that_the_exchange_was_not_authenticated() {
    let mut pair = Pair::new(pcmu().with_srtp(SrtpPolicy::Required));
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's call");
    let caller = report(&pair, call, true);
    assert!(caller.encrypted);
    assert_eq!(caller.media, "audio");
    assert_eq!(caller.key_exchange, Some(SrtpKeying::Sdes));
    // the offer names AEAD_AES_256_GCM first, and an answerer takes the
    // offerer's first line it supports (RFC 4568 §5.1.2)
    assert_eq!(caller.suite, Some(Suite::AeadAes256Gcm));
    assert!(
        !caller.authenticated,
        "an SDES key is as authentic as the signalling, which this layer cannot see"
    );
    assert!(!caller.awaiting_keys);
    assert_eq!(report(&pair, remote, false), caller);
}

#[test]
fn a_plain_call_reports_no_key_exchange() {
    let mut pair = Pair::new(pcmu());
    let call = pair.connect();
    let plain = report(&pair, call, true);
    assert!(!plain.encrypted);
    assert_eq!(plain.key_exchange, None);
    assert_eq!(plain.suite, None);
    assert!(!plain.authenticated);
}

#[cfg(feature = "dtls")]
#[test]
fn a_dtls_call_reports_waiting_then_the_suite_the_handshake_chose_and_authentication() {
    let mut pair = Pair::new(pcmu().with_srtp(SrtpPolicy::DtlsRequired));
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's call");
    let before = report(&pair, call, true);
    assert!(before.awaiting_keys);
    assert!(!before.encrypted);
    assert_eq!(before.key_exchange, Some(SrtpKeying::Dtls));
    assert_eq!(before.suite, None, "no transform runs before the keys land");
    assert!(!before.authenticated);

    pair.shake_hands(call, remote);
    let after = report(&pair, call, true);
    assert!(after.encrypted && !after.awaiting_keys);
    assert_eq!(after.suite, Some(Suite::AeadAes256Gcm));
    assert!(
        after.authenticated,
        "the far end's certificate matched the fingerprint its answer carried"
    );
    assert_eq!(report(&pair, remote, false), after);
}

/// 8.10: GCM in DTLS-SRTP is the account's to allow and to order, through
/// the suites its catalogue names.
#[cfg(feature = "dtls")]
#[test]
fn a_dtls_call_runs_the_suite_its_catalogue_prefers() {
    let aes_cm = pcmu()
        .with_srtp(SrtpPolicy::DtlsRequired)
        .with_srtp_suites(&[Suite::AesCm80, Suite::AeadAes128Gcm])
        .expect("two suites");
    let mut pair = Pair::asymmetric(aes_cm, pcmu().with_srtp(SrtpPolicy::DtlsRequired));
    let call = pair.connect();
    let remote = pair.callee.call().expect("the callee's call");
    pair.shake_hands(call, remote);
    // the caller wrote actpass and the callee's answer took active: the
    // callee is the client and offers its default four, the caller is the
    // server and chooses among them in its own order
    assert_eq!(report(&pair, call, true).suite, Some(Suite::AesCm80));
}

#[test]
fn the_suites_an_sdes_offer_names_are_the_catalogues_own_in_its_order() {
    let named = pcmu()
        .with_srtp(SrtpPolicy::Required)
        .with_srtp_suites(&[Suite::AesCm32, Suite::AesCm80])
        .expect("two suites");
    let mut pair = Pair::asymmetric(named, pcmu());
    let call = pair.connect();
    let offer = one_stream(&pair.callee.offer_received().expect("an offer"));
    let lines: Vec<String> = offer
        .attributes
        .iter()
        .filter(|attribute| attribute.name == "crypto")
        .filter_map(|attribute| attribute.value.clone())
        .map(|value| value.split(' ').take(2).collect::<Vec<_>>().join(" "))
        .collect();
    assert_eq!(
        lines,
        ["1 AES_CM_128_HMAC_SHA1_32", "2 AES_CM_128_HMAC_SHA1_80"]
    );
    assert_eq!(report(&pair, call, true).suite, Some(Suite::AesCm32));
}

#[test]
fn an_answer_takes_only_a_suite_its_catalogue_allows() {
    // the default offer names AEAD_AES_256_GCM then AES_CM_128_HMAC_SHA1_80;
    // an answerer that allows only the second takes the second
    let allowed = pcmu()
        .with_srtp_suites(&[Suite::AesCm80])
        .expect("one suite");
    let mut pair = Pair::asymmetric(pcmu().with_srtp(SrtpPolicy::Required), allowed);
    let call = pair.connect();
    assert_eq!(report(&pair, call, true).suite, Some(Suite::AesCm80));

    // and one that allows neither refuses the stream (RFC 4568 §7.1.2)
    let neither = pcmu()
        .with_srtp_suites(&[Suite::Aes256Cm32])
        .expect("one suite");
    let mut pair = Pair::asymmetric(pcmu().with_srtp(SrtpPolicy::Required), neither);
    let call = pair.connect();
    assert!(pair.caller.engine.session(call).is_none());
}

#[test]
fn a_list_of_suites_names_each_once_and_at_least_one() {
    assert_eq!(
        pcmu().with_srtp_suites(&[]).err(),
        Some(MediaError::NoSrtpSuite)
    );
    assert_eq!(
        pcmu()
            .with_srtp_suites(&[Suite::AesCm80, Suite::AesCm80])
            .err(),
        Some(MediaError::NoSrtpSuite)
    );
}

/// The call this end placed, answered in the clear by a far end that wrote
/// its own description: acknowledged, and hung up with a reason.
#[test]
fn a_placed_call_answered_in_the_clear_under_a_required_policy_is_hung_up_with_488() {
    let mut pair = Pair::asymmetric(pcmu().with_srtp(SrtpPolicy::Required), pcmu());
    let remote = pair.ring();
    let plain = "v=0\r\no=- 7 7 IN IP4 192.0.2.2\r\ns=-\r\nc=IN IP4 192.0.2.2\r\nt=0 0\r\n\
                 m=audio 40002 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
    pair.callee
        .agent
        .answer(
            remote,
            Some(std::sync::Arc::from(plain.as_bytes())),
            pair.now,
        )
        .expect("the application's own answer");
    let answered = pair.callee.outbound();
    for datagram in answered {
        pair.caller.deliver(&datagram, callee_sip(), pair.now);
    }
    pair.caller.drain(pair.now, false);
    assert!(
        pair.caller
            .media_events()
            .iter()
            .any(|event| matches!(event, MediaEvent::Failed(MediaError::SrtpRequired))),
        "{:?}",
        pair.caller.media_events()
    );
    let sent = pair.caller.outbound();
    let bye = sent
        .iter()
        .find(|bytes| bytes.starts_with(b"BYE "))
        .expect("the call is hung up");
    assert!(
        sent.iter().any(|bytes| bytes.starts_with(b"ACK ")),
        "the 2xx is acknowledged first (RFC 3261 §13.2.2.4)"
    );
    let mut scratch = ParseScratch::new();
    let message = parse_message(bye, &mut scratch, ParseMode::Lenient).expect("a BYE");
    let reason = String::from_utf8_lossy(
        message
            .header(HeaderName::Extension("Reason"))
            .unwrap_or_default(),
    )
    .into_owned();
    assert!(reason.contains("cause=488"), "{reason}");
}

#[cfg(feature = "dtls")]
mod fallback {
    use super::*;

    fn fallback() -> CodecCatalog {
        pcmu().with_srtp(SrtpPolicy::DtlsOrSdes)
    }

    #[test]
    fn the_offer_carries_a_fingerprint_and_crypto_lines_on_rtp_savp() {
        let mut pair = Pair::new(fallback());
        pair.connect();
        let offer = one_stream(&pair.callee.offer_received().expect("an offer"));
        assert_eq!(offer.proto, "RTP/SAVP");
        assert!(offer.attribute("fingerprint").is_some());
        assert_eq!(
            offer
                .attribute("setup")
                .and_then(|line| line.value.as_deref()),
            Some("actpass")
        );
        assert!(offer.attribute("crypto").is_some());
        assert!(offer.has_rtcp_mux(), "RFC 5764 §4.2, for the DTLS half");
    }

    #[test]
    fn a_peer_that_does_dtls_srtp_keys_the_call_with_the_handshake() {
        for answering in [
            fallback(),
            pcmu().with_srtp(SrtpPolicy::DtlsOffered),
            pcmu().with_srtp(SrtpPolicy::DtlsRequired),
        ] {
            let policy = answering.srtp();
            let mut pair = Pair::asymmetric(fallback(), answering);
            let call = pair.connect();
            let remote = pair.callee.call().expect("the callee's call");
            let answer = one_stream(&pair.caller.answer_received().expect("an answer"));
            assert!(answer.attribute("fingerprint").is_some(), "{policy:?}");
            assert!(answer.attribute("crypto").is_none(), "{policy:?}");
            pair.shake_hands(call, remote);
            let keyed = report(&pair, call, true);
            assert_eq!(keyed.key_exchange, Some(SrtpKeying::Dtls), "{policy:?}");
            assert!(keyed.encrypted && keyed.authenticated, "{policy:?}");
        }
    }

    #[test]
    fn a_peer_with_only_sdes_keys_the_call_with_a_crypto_line() {
        for answering in [
            pcmu().with_srtp(SrtpPolicy::Offered),
            pcmu().with_srtp(SrtpPolicy::Required),
            // one that does not offer still answers an offer that asked
            pcmu(),
        ] {
            let policy = answering.srtp();
            let mut pair = Pair::asymmetric(fallback(), answering);
            let call = pair.connect();
            let answer = one_stream(&pair.caller.answer_received().expect("an answer"));
            assert!(answer.attribute("crypto").is_some(), "{policy:?}");
            let keyed = report(&pair, call, true);
            assert_eq!(keyed.key_exchange, Some(SrtpKeying::Sdes), "{policy:?}");
            assert!(keyed.encrypted, "{policy:?}");
        }
    }

    #[test]
    fn answering_it_follows_the_offer_and_refuses_a_plain_one() {
        let mut pair = Pair::asymmetric(pcmu().with_srtp(SrtpPolicy::Offered), fallback());
        let call = pair.connect();
        assert_eq!(
            report(&pair, call, true).key_exchange,
            Some(SrtpKeying::Sdes),
            "crypto lines alone are answered with SDES"
        );

        let mut pair = Pair::asymmetric(pcmu(), fallback());
        let remote = pair.ring();
        let _ = pair.callee.outbound();
        let refused =
            pair.callee
                .engine
                .answer(&mut pair.callee.agent, remote, callee_media(), pair.now);
        assert_eq!(refused, Err(MediaError::SrtpRequired));
        assert_eq!(
            statuses(&pair.callee.outbound()),
            ["SIP/2.0 488 Not Acceptable Here"]
        );
    }
}

/// The policy per account: two accounts on one engine, one of them holding
/// its calls to SRTP and the other not.
#[test]
fn each_account_holds_its_calls_to_its_own_policy() {
    let mut pair = Pair::new(pcmu());
    let caller = pair.caller.account("alice", callee_sip());
    let strict = pair.callee.account("bob", caller_sip_address());
    let _relaxed = pair.callee.account("carol", caller_sip_address());
    pair.callee
        .engine
        .set_account_srtp(
            strict,
            AccountSrtp {
                policy: Some(SrtpPolicy::Required),
                suites: None,
                recording_in_clear: false,
            },
        )
        .expect("a policy");
    assert_eq!(
        pair.callee.engine.account_catalog(strict).srtp(),
        SrtpPolicy::Required
    );

    for (user, refused) in [("bob", true), ("carol", false)] {
        pair.caller
            .engine
            .place(
                &mut pair.caller.agent,
                caller,
                OutgoingCall::new(uri(&format!("sip:{user}@example.com")))
                    .to_address(UDP, callee_sip()),
                caller_media(),
                pair.now,
            )
            .expect("the INVITE goes");
        pair.caller.drain(pair.now, false);
        for datagram in pair.caller.outbound() {
            pair.callee
                .deliver(&datagram, caller_sip_address(), pair.now);
        }
        pair.callee.heard.clear();
        pair.callee.drain(pair.now, false);
        let call = pair
            .callee
            .heard
            .iter()
            .find_map(|event| match event {
                Event::Signalling(UaEvent::IncomingCall { call, .. }) => Some(*call),
                _ => None,
            })
            .expect("the INVITE arrived");
        let _ = pair.callee.outbound();
        let answered =
            pair.callee
                .engine
                .answer(&mut pair.callee.agent, call, callee_media(), pair.now);
        assert_eq!(answered.is_err(), refused, "{user}: {answered:?}");
        let sent = statuses(&pair.callee.outbound());
        if refused {
            assert_eq!(sent, ["SIP/2.0 488 Not Acceptable Here"], "{user}");
        } else {
            assert_eq!(sent, ["SIP/2.0 200 OK"], "{user}");
        }
    }
}

/// The account that places a call offers under its own policy and suites,
/// and a list of suites is checked when it is set.
#[test]
fn a_call_an_account_places_offers_under_its_own_policy() {
    let mut pair = Pair::new(pcmu());
    let caller = pair.caller.account("alice", callee_sip());
    let _ = pair.callee.account("carol", caller_sip_address());
    pair.caller
        .engine
        .set_account_srtp(
            caller,
            AccountSrtp {
                policy: Some(SrtpPolicy::Offered),
                suites: Some(vec![Suite::AesCm80]),
                recording_in_clear: false,
            },
        )
        .expect("a policy");
    pair.caller
        .engine
        .place(
            &mut pair.caller.agent,
            caller,
            OutgoingCall::new(uri("sip:carol@example.com")).to_address(UDP, callee_sip()),
            caller_media(),
            pair.now,
        )
        .expect("the INVITE goes");
    let invite = pair
        .caller
        .outbound()
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("an INVITE");
    let text = String::from_utf8_lossy(&invite);
    assert!(text.contains("RTP/SAVP"), "{text}");
    assert!(
        text.contains("a=crypto:1 AES_CM_128_HMAC_SHA1_80 "),
        "{text}"
    );
    assert!(!text.contains("AEAD_AES_256_GCM"), "{text}");

    // an account's own suites are checked when they are set
    assert_eq!(
        pair.caller.engine.set_account_srtp(
            caller,
            AccountSrtp {
                policy: None,
                suites: Some(Vec::new()),
                recording_in_clear: false,
            }
        ),
        Err(MediaError::NoSrtpSuite)
    );
}

fn caller_sip_address() -> std::net::SocketAddr {
    crate::tests::caller_sip()
}
