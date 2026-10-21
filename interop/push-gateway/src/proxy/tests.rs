// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The proxy driven by hand: every message written out, the clock moved by
//! the test, and every datagram it sends read back.

use super::*;

const APNS_PARAM: &str = "ABCDE12345.org.example.app.voip";
const APNS_PRID: &str = "00fc13adff78512";
const FCM_PRID: &str = "fcm-token-1";

fn own() -> SocketAddr {
    "192.0.2.10:5060".parse().expect("address")
}

fn pbx() -> SocketAddr {
    "192.0.2.20:5060".parse().expect("address")
}

fn device(port: u16) -> SocketAddr {
    SocketAddr::new("198.51.100.7".parse().expect("address"), port)
}

fn config() -> Config {
    Config {
        own: own(),
        pbx: pbx(),
        services: vec![
            Service {
                provider: "apns".into(),
                param: ParamRule::Apns {
                    team: Some("ABCDE12345".into()),
                },
            },
            Service {
                provider: "fcm".into(),
                param: ParamRule::Fcm {
                    project: Some("lab-project".into()),
                },
            },
        ],
        invite_bucket: Duration::from_secs(8),
        other_bucket: Duration::from_secs(5),
        min_expires: 180,
        only_push_proxy: false,
        secret: [7; 32],
    }
}

fn contact_uri(port: u16, provider: &str) -> String {
    match provider {
        "apns" => format!(
            "sip:alice@198.51.100.7:{port};pn-provider=apns;pn-param={APNS_PARAM};pn-prid={APNS_PRID}"
        ),
        "fcm" => format!(
            "sip:alice@198.51.100.7:{port};pn-provider=fcm;pn-param=lab-project;pn-prid={FCM_PRID}"
        ),
        other => format!("sip:alice@198.51.100.7:{port};{other}"),
    }
}

fn register(port: u16, cseq: u32, contact: &str, expires: u32) -> Vec<u8> {
    format!(
        "REGISTER sip:pbx.example SIP/2.0\r\n\
         Via: SIP/2.0/UDP 198.51.100.7:{port};branch=z9hG4bKreg{cseq};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@pbx.example>;tag=a1\r\n\
         To: <sip:alice@pbx.example>\r\n\
         Call-ID: reg@1\r\n\
         CSeq: {cseq} REGISTER\r\n\
         Contact: {contact}\r\n\
         Expires: {expires}\r\n\
         Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

fn invite(target: &str, branch: &str) -> Vec<u8> {
    format!(
        "INVITE {target} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: \"Bob\" <sip:bob@pbx.example>;tag=b1\r\n\
         To: <sip:alice@pbx.example>\r\n\
         Call-ID: call-{branch}\r\n\
         CSeq: 102 INVITE\r\n\
         Contact: <sip:bob@192.0.2.20:5060>\r\n\
         Content-Type: application/sdp\r\n\
         Content-Length: 3\r\n\r\nv=0"
    )
    .into_bytes()
}

fn message_request(target: &str, branch: &str) -> Vec<u8> {
    format!(
        "MESSAGE {target} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bK{branch};rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:bob@pbx.example>;tag=m1\r\n\
         To: <sip:alice@pbx.example>\r\n\
         Call-ID: msg-{branch}\r\n\
         CSeq: 1 MESSAGE\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: 2\r\n\r\nhi"
    )
    .into_bytes()
}

/// The datagrams in `actions`, read back, with where each went.
fn sent(actions: &[Action]) -> Vec<(SocketAddr, Message)> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Send { to, bytes } => Message::parse(bytes).map(|message| (*to, message)),
            _ => None,
        })
        .collect()
}

fn pushes(actions: &[Action]) -> Vec<PushRequest> {
    actions
        .iter()
        .filter_map(|action| match action {
            Action::Push(request) => Some(request.clone()),
            _ => None,
        })
        .collect()
}

fn only_send(actions: &[Action]) -> (SocketAddr, Message) {
    let mut all = sent(actions);
    assert_eq!(all.len(), 1, "one datagram expected, got {actions:#?}");
    all.remove(0)
}

/// The registrar's answer to what the proxy forwarded, `Contact`s and all.
fn answer(forwarded: &Message, code: u16, extra: &[(&str, String)]) -> Vec<u8> {
    let mut response = forwarded.response(code, "Answer", "pbx1");
    for (name, value) in extra {
        response.push_back(name, value.clone());
    }
    response.to_bytes()
}

/// A binding registered through the proxy at `port`; answers what the
/// device was sent back.
fn registered(
    gateway: &mut Gateway,
    port: u16,
    cseq: u32,
    provider: &str,
    now: Instant,
) -> Message {
    let actions = gateway.on_datagram(
        device(port),
        &register(
            port,
            cseq,
            &format!("<{}>", contact_uri(port, provider)),
            300,
        ),
        now,
    );
    let (to, forwarded) = only_send(&actions);
    assert_eq!(to, pbx());
    let held_as: Vec<String> = forwarded.all("Contact").map(str::to_owned).collect();
    let extra: Vec<(&str, String)> = held_as
        .iter()
        .map(|contact| ("Contact", format!("{contact};expires=300")))
        .collect();
    let actions = gateway.on_datagram(pbx(), &answer(&forwarded, 200, &extra), now);
    let back = sent(&actions);
    let (to, response) = back
        .iter()
        .find(|(_, message)| message.method() == Some("REGISTER"))
        .cloned()
        .expect("the 200 goes back");
    assert_eq!(to, device(port));
    response
}

#[test]
fn a_register_for_pushes_is_indicated_and_given_this_proxy_as_its_contact() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    let actions = gateway.on_datagram(
        device(40000),
        &register(
            40000,
            1,
            &format!(
                "<{}>;+sip.instance=\"<urn:uuid:1>\"",
                contact_uri(40000, "apns")
            ),
            300,
        ),
        now,
    );
    let (to, forwarded) = only_send(&actions);
    assert_eq!(to, pbx());
    assert_eq!(forwarded.first("Feature-Caps"), Some("*;+sip.pns=\"apns\""));
    let contact = forwarded.first("Contact").expect("contact");
    assert!(
        contact.starts_with(&format!(
            "<sip:alice@192.0.2.10:5060;pn-provider=apns;pn-param={APNS_PARAM};pn-prid={APNS_PRID}>"
        )),
        "{contact}"
    );
    assert!(contact.ends_with(";+sip.instance=\"<urn:uuid:1>\""));
    let via = Via::parse(forwarded.first("Via").expect("via")).expect("via parses");
    assert_eq!(via.sent_by, "192.0.2.10:5060");
    assert_eq!(forwarded.all("Via").count(), 2);
    assert_eq!(forwarded.first("Max-Forwards"), Some("69"));

    let held_as = format!("{contact};expires=300");
    let actions = gateway.on_datagram(
        pbx(),
        &answer(&forwarded, 200, &[("Contact", held_as)]),
        now,
    );
    let (to, response) = only_send(&actions);
    assert_eq!(to, device(40000));
    assert_eq!(response.all("Via").count(), 1);
    let caps = response.first("Feature-Caps").expect("caps");
    assert!(
        caps.starts_with("*;+sip.pns=\"apns\";+sip.pnspurr=\""),
        "{caps}"
    );
    assert!(!caps.contains("pnsreg"));
    // the device reads its own binding back
    assert!(
        response
            .first("Contact")
            .expect("contact")
            .starts_with(&format!("<{}>", contact_uri(40000, "apns")))
    );
}

#[test]
fn a_device_that_wakes_itself_is_told_how_early_to_refresh() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    let contact = format!("<{}>;+sip.pnsreg", contact_uri(40000, "fcm"));
    let actions = gateway.on_datagram(device(40000), &register(40000, 1, &contact, 300), now);
    let (_, forwarded) = only_send(&actions);
    let held_as = format!(
        "{};expires=300",
        forwarded.first("Contact").expect("contact")
    );
    let actions = gateway.on_datagram(
        pbx(),
        &answer(&forwarded, 200, &[("Contact", held_as)]),
        now,
    );
    let (_, response) = only_send(&actions);
    let caps = response.first("Feature-Caps").expect("caps");
    assert!(caps.contains(";+sip.pnsreg=\"121\""), "{caps}");
}

// the whole wake-up, one call from the push to the BYE
#[allow(clippy::too_many_lines)]
#[test]
fn an_invite_waits_in_the_bucket_until_the_woken_device_has_registered_again() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    let first = registered(&mut gateway, 40000, 1, "apns", now);
    let purr = first
        .first("Feature-Caps")
        .and_then(|caps| caps.split("+sip.pnspurr=\"").nth(1))
        .map(|rest| rest.trim_end_matches('"').to_owned())
        .expect("a purr");

    let target = SipUri::parse(&contact_uri(40000, "apns"))
        .expect("uri")
        .moved_to(own())
        .render();
    let actions = gateway.on_datagram(pbx(), &invite(&target, "inv1"), now);
    let back = sent(&actions);
    assert_eq!(back.len(), 1);
    assert_eq!(back[0].0, pbx());
    assert_eq!(back[0].1.status(), Some(100));
    assert!(back[0].1.to_tag().is_none());
    let asked = pushes(&actions);
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].kind, PushKind::Call);
    assert_eq!(asked[0].provider, "apns");
    assert_eq!(asked[0].prid, APNS_PRID);
    assert_eq!(asked[0].param.as_deref(), Some(APNS_PARAM));
    assert_eq!(asked[0].caller.as_deref(), Some("sip:bob@pbx.example"));
    assert_eq!(asked[0].name.as_deref(), Some("Bob"));
    assert_eq!(asked[0].call_id.as_deref(), Some("call-inv1"));
    assert_eq!(gateway.held(), 1);

    // the INVITE again, as UDP sends it: absorbed, not pushed twice
    let again = gateway.on_datagram(pbx(), &invite(&target, "inv1"), now);
    assert!(pushes(&again).is_empty());
    assert_eq!(gateway.held(), 1);
    let accepted = gateway.on_push(asked[0].id, &PushOutcome::Accepted("apns-id 1".into()), now);
    assert!(sent(&accepted).is_empty());

    // the device wakes on a socket of its own and refreshes
    let later = now + Duration::from_secs(2);
    let actions = gateway.on_datagram(
        device(41000),
        &register(41000, 2, &format!("<{}>", contact_uri(41000, "apns")), 300),
        later,
    );
    let (_, forwarded) = only_send(&actions);
    // the same binding at the PBX: the device moved, its push identity did not
    assert!(equivalent(
        &ContactValue::parse(forwarded.first("Contact").expect("contact"))
            .expect("value")
            .uri,
        &target
    ));
    assert_eq!(gateway.held(), 1, "held until the registrar has said yes");
    let held_as = format!(
        "{};expires=300",
        forwarded.first("Contact").expect("contact")
    );
    let actions = gateway.on_datagram(
        pbx(),
        &answer(&forwarded, 200, &[("Contact", held_as)]),
        later,
    );
    let out = sent(&actions);
    assert_eq!(out.len(), 2);
    let (to, invite) = out
        .iter()
        .find(|(_, message)| message.method() == Some("INVITE"))
        .cloned()
        .expect("the INVITE is released");
    assert_eq!(to, device(41000));
    assert_eq!(
        invite.request_uri(),
        Some(contact_uri(41000, "apns").as_str())
    );
    assert_eq!(
        invite.first("Record-Route"),
        Some("<sip:192.0.2.10:5060;lr>")
    );
    assert_eq!(invite.all("Via").count(), 2);
    assert_eq!(invite.body, b"v=0");
    assert_eq!(gateway.held(), 0);
    // the PURR is kept while it is young
    let refreshed = out
        .iter()
        .find(|(_, message)| message.method() == Some("REGISTER"))
        .map(|(_, message)| message.clone())
        .expect("the 200");
    assert!(
        refreshed
            .first("Feature-Caps")
            .expect("caps")
            .contains(&purr)
    );

    // the device's 180 goes back with its Contact at this proxy
    let mut ringing = invite.response(180, "Ringing", "dev1");
    ringing.push_back("Contact", format!("<{}>", "sip:alice@198.51.100.7:41000"));
    let actions = gateway.on_datagram(device(41000), &ringing.to_bytes(), later);
    let (to, ringing) = only_send(&actions);
    assert_eq!(to, pbx());
    assert_eq!(ringing.all("Via").count(), 1);
    let contact = ringing.first("Contact").expect("contact");
    assert_eq!(
        contact,
        "<sip:alice@192.0.2.10:5060;sipral-gw=198.51.100.7:41000~198.51.100.7:41000>"
    );

    // and the BYE the PBX sends there later reaches the device
    let bye = "BYE sip:alice@192.0.2.10:5060;sipral-gw=198.51.100.7:41000~198.51.100.7:41000 SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bKbye1\r\n\
         Route: <sip:192.0.2.10:5060;lr>\r\n\
         Max-Forwards: 70\r\n\
         From: \"Bob\" <sip:bob@pbx.example>;tag=b1\r\n\
         To: <sip:alice@pbx.example>;tag=dev1\r\n\
         Call-ID: call-inv1\r\n\
         CSeq: 103 BYE\r\n\
         Content-Length: 0\r\n\r\n";
    let actions = gateway.on_datagram(pbx(), bye.as_bytes(), later);
    let (to, bye) = only_send(&actions);
    assert_eq!(to, device(41000));
    assert_eq!(bye.request_uri(), Some("sip:alice@198.51.100.7:41000"));
    assert!(bye.first("Route").is_none());
}

#[test]
fn the_bucket_timer_answers_480_and_keeps_answering_it() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    registered(&mut gateway, 40000, 1, "apns", now);
    let target = SipUri::parse(&contact_uri(40000, "apns"))
        .expect("uri")
        .moved_to(own())
        .render();
    gateway.on_datagram(pbx(), &invite(&target, "inv2"), now);
    assert!(sent(&gateway.on_tick(now + Duration::from_secs(7))).is_empty());
    let actions = gateway.on_tick(now + Duration::from_secs(8));
    let (to, refused) = only_send(&actions);
    assert_eq!(to, pbx());
    assert_eq!(refused.status(), Some(480));
    assert!(refused.to_tag().is_some());
    assert_eq!(gateway.held(), 0);
    let later = now + Duration::from_secs(9);
    let (_, again) = only_send(&gateway.on_datagram(pbx(), &invite(&target, "inv2"), later));
    assert_eq!(again.status(), Some(480));
    let ack = format!(
        "ACK {target} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bKinv2;rport\r\n\
         Max-Forwards: 70\r\n\
         From: \"Bob\" <sip:bob@pbx.example>;tag=b1\r\n\
         To: {}\r\n\
         Call-ID: call-inv2\r\n\
         CSeq: 102 ACK\r\n\
         Content-Length: 0\r\n\r\n",
        refused.first("To").expect("to")
    );
    assert!(sent(&gateway.on_datagram(pbx(), ack.as_bytes(), later)).is_empty());
}

#[test]
fn a_failed_push_answers_480_at_once() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    registered(&mut gateway, 40000, 1, "apns", now);
    let target = SipUri::parse(&contact_uri(40000, "apns"))
        .expect("uri")
        .moved_to(own())
        .render();
    let actions = gateway.on_datagram(pbx(), &invite(&target, "inv3"), now);
    let id = pushes(&actions)[0].id;
    let actions = gateway.on_push(id, &PushOutcome::Failed("410 Unregistered".into()), now);
    let (_, refused) = only_send(&actions);
    assert_eq!(refused.status(), Some(480));
    assert_eq!(gateway.held(), 0);
}

#[test]
fn a_cancel_while_held_ends_the_invite_with_487() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    registered(&mut gateway, 40000, 1, "apns", now);
    let target = SipUri::parse(&contact_uri(40000, "apns"))
        .expect("uri")
        .moved_to(own())
        .render();
    gateway.on_datagram(pbx(), &invite(&target, "inv4"), now);
    let cancel = format!(
        "CANCEL {target} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bKinv4;rport\r\n\
         Max-Forwards: 70\r\n\
         From: \"Bob\" <sip:bob@pbx.example>;tag=b1\r\n\
         To: <sip:alice@pbx.example>\r\n\
         Call-ID: call-inv4\r\n\
         CSeq: 102 CANCEL\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let actions = gateway.on_datagram(pbx(), cancel.as_bytes(), now);
    let out = sent(&actions);
    let codes: Vec<(Option<&str>, Option<u16>)> = out
        .iter()
        .map(|(_, message)| (message.method(), message.status()))
        .collect();
    assert_eq!(
        codes,
        [(Some("CANCEL"), Some(200)), (Some("INVITE"), Some(487))]
    );
    assert_eq!(gateway.held(), 0);
}

#[test]
fn a_message_is_pushed_on_fcm_and_sent_straight_on_apns() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    registered(&mut gateway, 40000, 1, "fcm", now);
    registered(&mut gateway, 40002, 1, "apns", now);
    let fcm = SipUri::parse(&contact_uri(40000, "fcm"))
        .expect("uri")
        .moved_to(own())
        .render();
    let actions = gateway.on_datagram(pbx(), &message_request(&fcm, "m1"), now);
    assert!(sent(&actions).is_empty(), "no 100 to a non-INVITE");
    assert_eq!(pushes(&actions)[0].kind, PushKind::Message);
    assert_eq!(gateway.held(), 1);
    let actions = gateway.on_tick(now + Duration::from_secs(5));
    assert_eq!(only_send(&actions).1.status(), Some(480));

    let apns = SipUri::parse(&contact_uri(40002, "apns"))
        .expect("uri")
        .moved_to(own())
        .render();
    let actions = gateway.on_datagram(pbx(), &message_request(&apns, "m2"), now);
    assert!(pushes(&actions).is_empty());
    let (to, message) = only_send(&actions);
    assert_eq!(to, device(40002));
    assert_eq!(
        message.request_uri(),
        Some(contact_uri(40002, "apns").as_str())
    );
}

#[test]
fn too_short_unsupported_and_query_registers() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    let short = register(40000, 1, &format!("<{}>", contact_uri(40000, "apns")), 60);
    let (to, brief) = only_send(&gateway.on_datagram(device(40000), &short, now));
    assert_eq!(to, device(40000));
    assert_eq!(brief.status(), Some(423));
    assert_eq!(brief.first("Min-Expires"), Some("180"));

    // another team's topic: forwarded untouched, not answered for
    let other = "sip:alice@198.51.100.7:40000;pn-provider=apns;pn-param=ZZZZZ99999.org.example.app.voip;pn-prid=ab";
    let (to, forwarded) = only_send(&gateway.on_datagram(
        device(40000),
        &register(40000, 2, &format!("<{other}>"), 300),
        now,
    ));
    assert_eq!(to, pbx());
    assert!(forwarded.first("Feature-Caps").is_none());
    assert_eq!(
        forwarded.first("Contact"),
        Some(format!("<{other}>").as_str())
    );

    let mut strict = config();
    strict.only_push_proxy = true;
    let mut gateway = Gateway::new(strict);
    let webpush =
        "sip:alice@198.51.100.7:40000;pn-provider=webpush;pn-prid=https%3A%2F%2Fpush.example%2Fx";
    let (_, refused) = only_send(&gateway.on_datagram(
        device(40000),
        &register(40000, 3, &format!("<{webpush}>"), 300),
        now,
    ));
    assert_eq!(refused.status(), Some(555));

    let mut gateway = Gateway::new(config());
    let query = "sip:alice@198.51.100.7:40000;pn-provider";
    let (_, forwarded) = only_send(&gateway.on_datagram(
        device(40000),
        &register(40000, 4, &format!("<{query}>"), 300),
        now,
    ));
    let caps: Vec<&str> = forwarded.all("Feature-Caps").collect();
    assert_eq!(caps, ["*;+sip.pns=\"apns\"", "*;+sip.pns=\"fcm\""]);
    assert_eq!(
        forwarded.first("Contact"),
        Some(format!("<{query}>").as_str())
    );
    let held_as = format!("<{query}>;expires=300");
    let (_, response) = only_send(&gateway.on_datagram(
        pbx(),
        &answer(&forwarded, 200, &[("Contact", held_as)]),
        now,
    ));
    let caps: Vec<&str> = response.all("Feature-Caps").collect();
    assert_eq!(caps, ["*;+sip.pns=\"apns\"", "*;+sip.pns=\"fcm\""]);
}

#[test]
fn a_binding_about_to_lapse_is_pushed_to_refresh_and_then_forgotten() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    registered(&mut gateway, 40000, 1, "fcm", now);
    registered(&mut gateway, 40002, 1, "apns", now);
    assert!(pushes(&gateway.on_tick(now + Duration::from_secs(179))).is_empty());
    let actions = gateway.on_tick(now + Duration::from_secs(180));
    let asked = pushes(&actions);
    assert_eq!(asked.len(), 1, "APNs carries no refresh wake-up");
    assert_eq!(asked[0].kind, PushKind::Refresh);
    assert_eq!(asked[0].provider, "fcm");
    assert!(pushes(&gateway.on_tick(now + Duration::from_secs(200))).is_empty());
    gateway.on_tick(now + Duration::from_secs(300));
    let fcm = SipUri::parse(&contact_uri(40000, "fcm"))
        .expect("uri")
        .moved_to(own())
        .render();
    let actions = gateway.on_datagram(pbx(), &invite(&fcm, "late"), now + Duration::from_secs(301));
    assert!(pushes(&actions).is_empty());
    assert_eq!(only_send(&actions).1.status(), Some(480));
}

#[test]
fn removing_the_binding_without_its_token_stops_the_pushes() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    registered(&mut gateway, 40000, 1, "apns", now);
    // §4.1.2: the removal carries no pn-prid
    let removal =
        format!("<sip:alice@198.51.100.7:40000;pn-provider=apns;pn-param={APNS_PARAM}>;expires=0");
    let (_, forwarded) =
        only_send(&gateway.on_datagram(device(40000), &register(40000, 2, &removal, 0), now));
    assert!(
        forwarded
            .first("Contact")
            .expect("contact")
            .starts_with("<sip:alice@192.0.2.10:5060;"),
        "the removal has to name the binding the PBX holds"
    );
    gateway.on_datagram(pbx(), &answer(&forwarded, 200, &[]), now);
    let target = SipUri::parse(&contact_uri(40000, "apns"))
        .expect("uri")
        .moved_to(own())
        .render();
    let actions = gateway.on_datagram(pbx(), &invite(&target, "gone"), now);
    assert!(pushes(&actions).is_empty());
    assert_eq!(only_send(&actions).1.status(), Some(480));
}

#[test]
fn a_challenge_keeps_the_request_held_and_a_refusal_releases_it_with_480() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    registered(&mut gateway, 40000, 1, "apns", now);
    let target = SipUri::parse(&contact_uri(40000, "apns"))
        .expect("uri")
        .moved_to(own())
        .render();
    gateway.on_datagram(pbx(), &invite(&target, "inv5"), now);
    let refresh = register(40000, 2, &format!("<{}>", contact_uri(40000, "apns")), 300);
    let (_, forwarded) = only_send(&gateway.on_datagram(device(40000), &refresh, now));
    let actions = gateway.on_datagram(pbx(), &answer(&forwarded, 401, &[]), now);
    assert_eq!(only_send(&actions).1.status(), Some(401));
    assert_eq!(gateway.held(), 1);
    let refresh = register(40000, 3, &format!("<{}>", contact_uri(40000, "apns")), 300);
    let (_, forwarded) = only_send(&gateway.on_datagram(device(40000), &refresh, now));
    let actions = gateway.on_datagram(pbx(), &answer(&forwarded, 403, &[]), now);
    let codes: Vec<Option<u16>> = sent(&actions)
        .iter()
        .map(|(_, message)| message.status())
        .collect();
    assert_eq!(codes, [Some(480), Some(403)]);
    assert_eq!(gateway.held(), 0);
}

#[test]
fn a_request_inside_a_dialog_with_a_purr_is_held_on_fcm() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    let response = registered(&mut gateway, 40000, 1, "fcm", now);
    let purr = response
        .first("Feature-Caps")
        .and_then(|caps| caps.split("+sip.pnspurr=\"").nth(1))
        .map(|rest| rest.trim_end_matches('"').to_owned())
        .expect("a purr");
    let target = format!(
        "sip:alice@192.0.2.10:5060;pn-purr={purr};sipral-gw=198.51.100.7:40000~198.51.100.7:40000"
    );
    let update = format!(
        "UPDATE {target} SIP/2.0\r\n\
         Via: SIP/2.0/UDP 192.0.2.20:5060;branch=z9hG4bKupd1\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:bob@pbx.example>;tag=b1\r\n\
         To: <sip:alice@pbx.example>;tag=dev1\r\n\
         Call-ID: call-x\r\n\
         CSeq: 5 UPDATE\r\n\
         Content-Length: 0\r\n\r\n"
    );
    let actions = gateway.on_datagram(pbx(), update.as_bytes(), now);
    assert_eq!(pushes(&actions)[0].kind, PushKind::Dialog);
    assert_eq!(gateway.held(), 1);
    let refresh = register(40004, 2, &format!("<{}>", contact_uri(40004, "fcm")), 300);
    let (_, forwarded) = only_send(&gateway.on_datagram(device(40004), &refresh, now));
    let held_as = format!(
        "{};expires=300",
        forwarded.first("Contact").expect("contact")
    );
    let out = sent(&gateway.on_datagram(
        pbx(),
        &answer(&forwarded, 200, &[("Contact", held_as)]),
        now,
    ));
    let (to, update) = out
        .iter()
        .find(|(_, message)| message.method() == Some("UPDATE"))
        .cloned()
        .expect("released");
    assert_eq!(to, device(40004));
    assert_eq!(
        update.request_uri(),
        Some(format!("sip:alice@198.51.100.7:40000;pn-purr={purr}").as_str())
    );
}

#[test]
fn an_unknown_binding_and_an_ordinary_request() {
    let mut gateway = Gateway::new(config());
    let now = Instant::now();
    let target = SipUri::parse(&contact_uri(40000, "apns"))
        .expect("uri")
        .moved_to(own())
        .render();
    let actions = gateway.on_datagram(pbx(), &invite(&target, "nobody"), now);
    assert_eq!(only_send(&actions).1.status(), Some(480));
    // a REGISTER that asks for nothing passes untouched
    let plain = register(40000, 1, "<sip:alice@198.51.100.7:40000>", 300);
    let (to, forwarded) = only_send(&gateway.on_datagram(device(40000), &plain, now));
    assert_eq!(to, pbx());
    assert_eq!(
        forwarded.first("Contact"),
        Some("<sip:alice@198.51.100.7:40000>")
    );
    assert!(forwarded.first("Feature-Caps").is_none());
    // and a device's INVITE goes to the PBX with its Contact at this proxy
    let outgoing = "INVITE sip:9000@pbx.example SIP/2.0\r\n\
         Via: SIP/2.0/UDP 198.51.100.7:40000;branch=z9hG4bKout1;rport\r\n\
         Max-Forwards: 70\r\n\
         From: <sip:alice@pbx.example>;tag=a9\r\n\
         To: <sip:9000@pbx.example>\r\n\
         Call-ID: out@1\r\n\
         CSeq: 1 INVITE\r\n\
         Contact: <sip:alice@198.51.100.7:40000>\r\n\
         Content-Length: 0\r\n\r\n";
    let (to, forwarded) = only_send(&gateway.on_datagram(device(40000), outgoing.as_bytes(), now));
    assert_eq!(to, pbx());
    assert_eq!(
        forwarded.first("Contact"),
        Some("<sip:alice@192.0.2.10:5060;sipral-gw=198.51.100.7:40000~198.51.100.7:40000>")
    );
    assert!(forwarded.first("Record-Route").is_none());
}

#[test]
fn flows_decode_for_every_host_form() {
    let gateway = Gateway::new(config());
    for (host, port) in [
        ("198.51.100.7", Some(5062)),
        ("phone.example", None),
        ("[2001:db8::1]", Some(5060)),
        ("[2001:db8::2]", None),
    ] {
        let uri = SipUri {
            scheme: "sip",
            userinfo: "alice".into(),
            host: host.into(),
            port,
            params: vec![("transport".into(), Some("udp".into()))],
            headers: String::new(),
        };
        let flow: SocketAddr = "[2001:db8::9]:40000".parse().expect("address");
        let encoded = gateway.encode_flow(&uri, flow);
        let reread = SipUri::parse(&encoded.render()).expect("encoded parses");
        let (restored, back) = Gateway::decode_flow(&reread).expect("decodes");
        assert_eq!(back, flow);
        assert_eq!(restored.render(), uri.render());
    }
}
