// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Messages written out octet by octet from Q.763's figures and tables, and
//! read; the builder made to write the same octets from typed values.

use super::*;
use crate::msg::{ParseMode, ParseScratch, parse as parse_sip};

/// An IAM for a call diverted twice, the caller's number withheld, laid out
/// as Table 32 and Figure 3 have it.
const IAM: &[u8] = &[
    0x01, // message type: initial address
    0x00, // nature of connection: no satellite, no continuity check, no echo device
    0x60,
    0x01, // forward call: national, ISUP all the way (F), ISUP not required (HG = 01); ISDN access (I)
    0x0a, // calling party's category: ordinary subscriber
    0x03, // transmission medium requirement: 3.1 kHz audio
    0x02, // pointer to the called party number: two octets on
    0x08, // pointer to the optional part: eight octets on
    0x06, 0x83, 0x90, 0x20, 0x21, 0x43,
    0x05, // called: odd, national; INN, ISDN; 0212345 and filler
    0x0a, 0x08, 0x04, 0x17, 0x44, 0x61, 0x23, 0x69, 0x10,
    0x32, // calling: even, international; ISDN, restricted, network provided; 441632960123
    0x0b, 0x07, 0x04, 0x10, 0x44, 0x61, 0x23, 0x69,
    0x70, // redirecting: even, international; ISDN, allowed; 4416329607
    0x28, 0x08, 0x84, 0x10, 0x44, 0x61, 0x23, 0x69, 0x50,
    0x05, // original called: odd, international; 44163296055 and filler
    0x13, 0x02, 0x33,
    0x22, // redirection information: diverted, first unconditional; counter 2, last no reply
    0xc0, 0x05, 0x06, 0x04, 0x10, 0x44,
    0x02, // generic number: additional calling party, international, not screened; 4420
    0x00, // end of optional parameters
];

/// An ACM: charge, subscriber free, ordinary subscriber; ISUP all the way,
/// terminating access ISDN; no optional part.
const ACM: &[u8] = &[0x06, 0x16, 0x14, 0x00];

/// A CPG reporting alerting, with backward call indicators.
const CPG: &[u8] = &[0x2c, 0x01, 0x01, 0x11, 0x02, 0x16, 0x14, 0x00];

/// An ANM with a connected number: odd, international; network provided;
/// 12025550100 and filler.
const ANM: &[u8] = &[
    0x09, 0x01, 0x21, 0x08, 0x84, 0x13, 0x21, 0x20, 0x55, 0x05, 0x01, 0x00, 0x00,
];

/// A CON with the same backward call indicators as the ACM.
const CON: &[u8] = &[0x07, 0x16, 0x14, 0x00];

/// A REL, cause 16 normal call clearing, at the public network serving the
/// remote user.
const REL: &[u8] = &[0x0c, 0x02, 0x00, 0x02, 0x84, 0x90];

/// A REL whose cause carries Q.850's octet 3a: user busy.
const REL_RECOMMENDATION: &[u8] = &[0x0c, 0x02, 0x00, 0x03, 0x04, 0x80, 0x91];

/// An RLC with nothing in it.
const RLC: &[u8] = &[0x10, 0x00];

fn number(
    nature: Nature,
    digits: &str,
    presentation: Option<Presentation>,
    screening: Option<Screening>,
) -> Number {
    let mut out = Number::new(nature, digits);
    out.presentation = presentation;
    out.screening = screening;
    out
}

#[test]
fn an_iam_reads_into_its_numbers_and_indicators() {
    let iam = parse(IAM).unwrap();
    assert_eq!(iam.message_type(), MessageType::InitialAddress);
    assert_eq!(
        iam.nature_of_connection(),
        Some(NatureOfConnection {
            satellites: 0,
            continuity_check: 0,
            echo_control: false
        })
    );
    let forward = iam.forward_call().unwrap();
    assert!(!forward.international && forward.isup_all_the_way && forward.isdn_access);
    assert_eq!(forward.isup_preference, 1);
    assert_eq!(iam.calling_category(), Some(0x0a));
    assert_eq!(iam.transmission_medium(), Some(3));

    let called = iam.called_party().unwrap();
    assert_eq!(&*called.digits, "0212345");
    assert_eq!(called.nature, Nature::National);
    assert!(called.inn_not_allowed);
    assert_eq!((called.presentation, called.screening), (None, None));

    let calling = iam.calling_party().unwrap();
    assert_eq!(calling.text(), "+441632960123");
    assert_eq!(calling.presentation, Some(Presentation::Restricted));
    assert_eq!(calling.screening, Some(Screening::Network));
    assert!(calling.presentation.unwrap().withheld() && !calling.incomplete);

    let redirecting = iam.redirecting().unwrap();
    assert_eq!(redirecting.text(), "+4416329607");
    assert_eq!(redirecting.presentation, Some(Presentation::Allowed));
    assert_eq!(redirecting.screening, None);
    assert_eq!(iam.original_called().unwrap().text(), "+44163296055");

    let redirection = iam.redirection().unwrap();
    assert_eq!(redirection.indicator, RedirectingIndicator::Diverted);
    assert_eq!(redirection.original_reason, RedirectReason::Unconditional);
    assert_eq!(redirection.counter, Some(2));
    assert_eq!(redirection.reason, Some(RedirectReason::NoReply));
    assert_eq!(redirection.reason.unwrap().diversion_reason(), "no-answer");

    let generic: Vec<GenericNumber> = iam.generic_numbers().collect();
    assert_eq!(generic.len(), 1);
    assert_eq!(generic[0].qualifier, NumberQualifier::AdditionalCalling);
    assert_eq!(generic[0].number.text(), "+4420");
    assert_eq!(
        generic[0].number.screening,
        Some(Screening::UserNotVerified)
    );
    assert_eq!(iam.cause(), None);
    assert_eq!(iam.parameters().count(), 5);
}

#[test]
fn the_backward_messages_read_their_indicators_event_and_connected_number() {
    let acm = parse(ACM).unwrap();
    let backward = acm.backward_call().unwrap();
    assert_eq!(backward.charge, 2);
    assert_eq!(backward.called_status, CalledStatus::SubscriberFree);
    assert_eq!(backward.called_category, 1);
    assert!(backward.isup_all_the_way && backward.isdn_access && !backward.interworking);
    assert_eq!(acm.parameters().count(), 0);

    let cpg = parse(CPG).unwrap();
    assert_eq!(cpg.event(), Some(CallEvent::new(EventKind::Alerting)));
    assert_eq!(cpg.backward_call(), Some(backward));

    let anm = parse(ANM).unwrap();
    assert_eq!(anm.message_type(), MessageType::Answer);
    let connected = anm.connected().unwrap();
    assert_eq!(connected.text(), "+12025550100");
    assert_eq!(connected.screening, Some(Screening::Network));
    assert_eq!(anm.backward_call(), None);

    assert_eq!(parse(CON).unwrap().backward_call(), Some(backward));
    assert_eq!(parse(&[0x09, 0x00]).unwrap().parameters().count(), 0);
}

#[test]
fn a_rel_carries_its_cause_and_its_location() {
    let rel = parse(REL).unwrap();
    let cause = rel.cause().unwrap();
    assert_eq!(cause.value, 16);
    assert_eq!(cause.location, Location::PublicRemote);
    assert_eq!(cause.coding, CodingStandard::Itu);
    assert_eq!(cause.name(), Some("Normal call clearing"));
    assert_eq!(cause.class(), 1);

    let busy = parse(REL_RECOMMENDATION).unwrap().cause().unwrap();
    assert_eq!((busy.value, busy.location), (17, Location::PublicRemote));
    assert_eq!(busy.name(), Some("User busy"));

    let rlc = parse(RLC).unwrap();
    assert_eq!(rlc.message_type(), MessageType::ReleaseComplete);
    assert_eq!(rlc.cause(), None);
}

#[test]
fn every_other_message_type_is_recognised_and_left_as_bytes() {
    let confusion = parse(&[0x2f, 0x02, 0x00, 0x02, 0x80, 0xe1]).unwrap();
    assert_eq!(confusion.message_type(), MessageType::Other(0x2f));
    assert_eq!(confusion.message_type().name(), Some("Confusion"));
    assert_eq!(confusion.parameters().count(), 0);
    assert_eq!(confusion.cause(), None);
    assert_eq!(confusion.bytes().len(), 6);
    assert_eq!(MessageType::Other(0xfe).name(), None);
    assert_eq!(MessageType::of(0x0c).to_string(), "REL");
    assert_eq!(MessageType::Other(0x33).to_string(), "Facility");
}

#[test]
fn a_message_that_does_not_fit_is_refused_and_nothing_panics() {
    assert_eq!(parse(&[]).unwrap_err(), IsupError::Empty);
    assert_eq!(
        parse(&[0x01, 0x00, 0x60]).unwrap_err(),
        IsupError::Truncated("mandatory fixed part")
    );
    assert_eq!(
        parse(&[0x0c]).unwrap_err(),
        IsupError::Truncated("pointers")
    );
    // a pointer of zero to a mandatory parameter, and one past the end
    assert_eq!(
        parse(&[0x0c, 0x00, 0x00]).unwrap_err(),
        IsupError::BadPointer("mandatory variable part")
    );
    assert_eq!(
        parse(&[0x0c, 0x09, 0x00]).unwrap_err(),
        IsupError::BadPointer("mandatory variable part")
    );
    // a length that runs past the end, mandatory and optional
    assert_eq!(
        parse(&[0x0c, 0x02, 0x00, 0x05, 0x84]).unwrap_err(),
        IsupError::Truncated("mandatory variable part")
    );
    assert_eq!(
        parse(&[0x06, 0x16, 0x14, 0x01, 0x12, 0x09, 0x84]).unwrap_err(),
        IsupError::Truncated("optional part")
    );
    assert_eq!(
        parse(&[0x06, 0x16, 0x14, 0x07]).unwrap_err(),
        IsupError::BadPointer("optional part")
    );
    // without the closing zero octet, the optional part ends with the input
    let open = parse(&[0x06, 0x16, 0x14, 0x01, 0x12, 0x02, 0x84, 0x91]).unwrap();
    assert_eq!(open.cause().unwrap().value, 17);
    // every prefix of every vector either reads or is refused
    for vector in [IAM, ACM, CPG, ANM, CON, REL, REL_RECOMMENDATION, RLC] {
        for end in 0..vector.len() {
            let _ = parse(&vector[..end]).map(|message| {
                let _ = (
                    message.calling_party(),
                    message.cause(),
                    message.redirection(),
                );
                message.generic_numbers().count()
            });
        }
    }
}

#[test]
fn a_number_with_nothing_to_show_has_no_digits_and_a_short_one_still_reads() {
    // §3.10 Note 1: address not available, octets 3 on omitted
    let unavailable = Number::calling(&[0x00, 0x0b]).unwrap();
    assert_eq!(unavailable.presentation, Some(Presentation::NotAvailable));
    assert_eq!(unavailable.screening, Some(Screening::Network));
    assert!(unavailable.digits.is_empty() && unavailable.text().is_empty());
    assert!(!unavailable.is_dialable());
    // an odd flag with no signal at all is no signal, not a panic
    assert!(Number::calling(&[0x84, 0x13]).unwrap().digits.is_empty());
    assert_eq!(Number::calling(&[0x84]), None);
    // the operator codes and ST read as their values
    assert_eq!(
        &*Number::called(&[0x02, 0x10, 0xcb, 0xf1]).unwrap().digits,
        "BC1F"
    );
}

#[test]
fn the_builder_writes_the_octets_the_figures_give() {
    let iam = IsupBuilder::initial_address(
        NatureOfConnection {
            satellites: 0,
            continuity_check: 0,
            echo_control: false,
        },
        ForwardCall {
            isup_all_the_way: true,
            isup_preference: 1,
            isdn_access: true,
            ..ForwardCall::default()
        },
        0x0a,
        3,
        &{
            let mut called = number(Nature::National, "0212345", None, None);
            called.inn_not_allowed = true;
            called
        },
    )
    .calling_party(&number(
        Nature::International,
        "441632960123",
        Some(Presentation::Restricted),
        Some(Screening::Network),
    ))
    .redirecting(&number(
        Nature::International,
        "4416329607",
        Some(Presentation::Allowed),
        None,
    ))
    .original_called(&number(
        Nature::International,
        "44163296055",
        Some(Presentation::Allowed),
        None,
    ))
    .redirection(Redirection::diverted(
        RedirectReason::NoReply,
        RedirectReason::Unconditional,
        2,
    ))
    .generic_number(&GenericNumber::new(
        NumberQualifier::AdditionalCalling,
        number(
            Nature::International,
            "4420",
            Some(Presentation::Allowed),
            Some(Screening::UserNotVerified),
        ),
    ))
    .build()
    .unwrap();
    assert_eq!(iam, IAM);

    let backward = BackwardCall {
        charge: 2,
        called_status: CalledStatus::SubscriberFree,
        called_category: 1,
        isup_all_the_way: true,
        isdn_access: true,
        ..BackwardCall::default()
    };
    assert_eq!(
        IsupBuilder::address_complete(backward).build().unwrap(),
        ACM
    );
    assert_eq!(
        IsupBuilder::call_progress(CallEvent::new(EventKind::Alerting))
            .backward_call(backward)
            .build()
            .unwrap(),
        CPG
    );
    assert_eq!(
        IsupBuilder::answer()
            .connected(&number(
                Nature::International,
                "12025550100",
                Some(Presentation::Allowed),
                Some(Screening::Network)
            ))
            .build()
            .unwrap(),
        ANM
    );
    assert_eq!(IsupBuilder::connect(backward).build().unwrap(), CON);
    assert_eq!(
        IsupBuilder::release(Cause::new(16, Location::PublicRemote))
            .build()
            .unwrap(),
        REL
    );
    assert_eq!(IsupBuilder::release_complete().build().unwrap(), RLC);
}

#[test]
fn the_builder_refuses_what_the_type_does_not_have() {
    let wrong_fixed = IsupBuilder::new(MessageType::AddressComplete).fixed(&[0x16]);
    assert!(matches!(wrong_fixed.build(), Err(IsupError::Unwritable(_))));
    let no_cause = IsupBuilder::new(MessageType::Release);
    assert!(matches!(no_cause.build(), Err(IsupError::Unwritable(_))));
    let other = IsupBuilder::new(MessageType::Other(0x2f));
    assert!(matches!(other.build(), Err(IsupError::Unwritable(_))));
    let named_zero = IsupBuilder::answer().optional(0, &[1]);
    assert!(matches!(named_zero.build(), Err(IsupError::Unwritable(_))));
    let mut bad = Number::new(Nature::International, "44");
    bad.digits = Box::from("4*4");
    assert!(matches!(
        IsupBuilder::answer().connected(&bad).build(),
        Err(IsupError::Unwritable(_))
    ));
    let long = Number::new(Nature::Unknown, &"1".repeat(600));
    assert!(matches!(
        IsupBuilder::answer().connected(&long).build(),
        Err(IsupError::Unwritable(_))
    ));
}

#[test]
fn what_the_builder_writes_reads_back() {
    let caller = Number::new(Nature::National, "2125550123").presented(Presentation::Allowed);
    let bytes = IsupBuilder::initial_address(
        NatureOfConnection {
            satellites: 1,
            continuity_check: 2,
            echo_control: true,
        },
        ForwardCall {
            international: true,
            interworking: true,
            ..ForwardCall::default()
        },
        0x0f,
        0,
        &Number::new(Nature::International, "15551234567"),
    )
    .calling_party(&caller)
    .cause(Cause::new(31, Location::Transit))
    .build()
    .unwrap();
    let read = parse(&bytes).unwrap();
    assert_eq!(read.calling_party().unwrap(), caller);
    assert_eq!(read.called_party().unwrap().text(), "+15551234567");
    let nature = read.nature_of_connection().unwrap();
    assert_eq!(
        (
            nature.satellites,
            nature.continuity_check,
            nature.echo_control
        ),
        (1, 2, true)
    );
    let forward = read.forward_call().unwrap();
    assert!(forward.international && forward.interworking);
    assert_eq!(read.calling_category(), Some(0x0f));
    assert_eq!(read.cause().unwrap().value, 31);
}

fn message(content_type: &str, extra: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!(
        "INVITE sip:bob@example.com SIP/2.0\r\n\
         Via: SIP/2.0/UDP gw.example.net;branch=z9hG4bKisup\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:anonymous@anonymous.invalid>;tag=1\r\n\
         To: <sip:bob@example.com>\r\n\
         Call-ID: isup@gw\r\n\
         CSeq: 1 INVITE\r\n\
         Content-Type: {content_type}\r\n\
         {extra}Content-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

#[test]
fn the_body_is_found_alone_or_beside_the_session_description() {
    let alone = message(
        "application/ISUP;version=itu-t92+",
        "Content-Disposition: signal;handling=optional\r\n",
        REL,
    );
    let mut scratch = ParseScratch::new();
    let raw = parse_sip(&alone, &mut scratch, ParseMode::Strict).unwrap();
    let found = IsupBody::find(&raw).unwrap();
    assert_eq!(found.bytes(), REL);
    assert_eq!(found.handling(), crate::msg::Handling::Optional);
    assert_eq!(found.variant(), Variant::Itu);
    assert_eq!(found.parse().unwrap().cause().unwrap().value, 16);
    assert!(raw.session_body().is_empty(), "ISUP alone describes no session");

    let mut body = b"--b\r\nContent-Type: application/sdp\r\n\r\nv=0\r\n\r\n--b\r\n\
Content-Type: application/ISUP; version=nxv3; base=ansi00\r\n\
Content-Disposition: signal; handling=required\r\n\r\n"
        .to_vec();
    body.extend_from_slice(IAM);
    body.extend_from_slice(b"\r\n--b--\r\n");
    let mixed = message("multipart/mixed;boundary=b", "", &body);
    let mut scratch = ParseScratch::new();
    let raw = parse_sip(&mixed, &mut scratch, ParseMode::Strict).unwrap();
    let found = IsupBody::find(&raw).unwrap();
    assert_eq!(found.bytes(), IAM);
    assert_eq!(found.handling(), crate::msg::Handling::Required);
    assert_eq!(found.version().as_deref(), Some(&b"nxv3"[..]));
    assert_eq!(found.variant(), Variant::Ansi);
    assert!(!found.variant().readable());
    assert_eq!(raw.session_body(), b"v=0\r\n");

    let plain = message("application/sdp", "", b"v=0\r\n");
    let mut scratch = ParseScratch::new();
    let raw = parse_sip(&plain, &mut scratch, ParseMode::Strict).unwrap();
    assert!(IsupBody::find(&raw).is_none());
    assert_eq!(raw.session_body(), b"v=0\r\n");
}
