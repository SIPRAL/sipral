// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Audit probes. Not part of the delivered suite: each one asserts the
//! behaviour the surrounding documentation promises, so a failure here names a
//! promise the tree does not keep.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, RawMessage, parse};

use crate::account::Account;
use crate::agent::UserAgent;
use crate::call::OutgoingCall;
use crate::event::RegistrationState;
use crate::subscription::Subscribe;
use crate::{EndpointConfig, Input, TransportId, TransportProtocol, Uri};

const UDP: TransportId = TransportId(1);

fn local() -> SocketAddr {
    "192.0.2.1:5060".parse().expect("a local address")
}

fn registrar() -> SocketAddr {
    "192.0.2.9:5060".parse().expect("the registrar's address")
}

fn uri(text: &str) -> Uri {
    Uri::parse_str(text).expect("a URI")
}

fn agent(now: Instant) -> UserAgent {
    let mut agent = UserAgent::new(EndpointConfig::default(), [11; 32]).unwrap();
    agent
        .receive(
            Input::TransportBound {
                transport: UDP,
                protocol: TransportProtocol::Udp,
                local: local(),
                remote: None,
            },
            now,
        )
        .expect("binding a transport");
    agent
}

fn account() -> Account {
    Account::new(
        uri("sip:alice@example.com"),
        uri("sip:example.com"),
        uri("sip:alice@192.0.2.1"),
        UDP,
        registrar(),
    )
}

fn transmits(agent: &mut UserAgent) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while let Some(transmit) = agent.poll_transmit() {
        out.push(transmit.payload.to_vec());
    }
    out
}

fn drop_events(agent: &mut UserAgent) {
    while agent.poll_event().is_some() {}
}

fn with<T>(bytes: &[u8], f: impl FnOnce(&RawMessage<'_>) -> T) -> T {
    let mut scratch = ParseScratch::new();
    f(&parse(bytes, &mut scratch, ParseMode::Lenient).expect("a message"))
}

fn header(bytes: &[u8], name: HeaderName<'_>) -> Vec<u8> {
    with(bytes, |message| {
        message.header(name).unwrap_or_default().to_vec()
    })
}

fn text(bytes: &[u8], name: HeaderName<'_>) -> String {
    String::from_utf8_lossy(&header(bytes, name)).into_owned()
}

/// A notification answering a SUBSCRIBE this end sent. §4.4.1 matches it on
/// the `Call-ID`, the `To` tag — the `From` tag of the SUBSCRIBE — and the
/// `Event`, all three taken from that request here.
fn notify(subscribe: &[u8], cseq: u32, tag: &str, state: &str) -> Vec<u8> {
    format!(
        "NOTIFY sip:alice@192.0.2.1 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.9:5060;branch=z9hG4bKn{tag}{cseq}\r\n\
Max-Forwards: 70\r\n\
From: {};tag={tag}\r\n\
To: {}\r\n\
Call-ID: {}\r\n\
CSeq: {cseq} NOTIFY\r\n\
Contact: <sip:notifier@192.0.2.9>\r\n\
Event: dialog\r\n\
Subscription-State: {state}\r\n\
Content-Length: 0\r\n\r\n",
        text(subscribe, HeaderName::To),
        text(subscribe, HeaderName::From),
        text(subscribe, HeaderName::CallId),
    )
    .into_bytes()
}

fn deliver(agent: &mut UserAgent, bytes: &[u8], now: Instant) {
    agent
        .receive(
            Input::Datagram {
                transport: UDP,
                remote: registrar(),
                local: local(),
                data: bytes,
            },
            now,
        )
        .expect("a well formed datagram");
}

fn reply(request: &[u8], status: u16, reason: &str, extra: &str) -> Vec<u8> {
    let mut out = format!("SIP/2.0 {status} {reason}\r\n").into_bytes();
    for (name, value) in [
        ("Via", header(request, HeaderName::Via)),
        ("From", header(request, HeaderName::From)),
        ("To", header(request, HeaderName::To)),
        ("Call-ID", header(request, HeaderName::CallId)),
        ("CSeq", header(request, HeaderName::CSeq)),
    ] {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(&value);
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(extra.as_bytes());
    out.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    out
}

fn granted(request: &[u8], seconds: u32) -> Vec<u8> {
    reply(
        request,
        200,
        "OK",
        &format!("Contact: <sip:alice@192.0.2.1>;expires={seconds}\r\n"),
    )
}

/// §3.1.1's own answer to a SUBSCRIBE, ahead of the NOTIFY that actually
/// grants the subscription -- required so its client transaction concludes
/// rather than sitting there until Timer F.
fn subscribed(request: &[u8], seconds: u32) -> Vec<u8> {
    reply(request, 200, "OK", &format!("Expires: {seconds}\r\n"))
}

// -- 1. a thawed registration must meet the recovery ladder -------------------

#[test]
fn a_restored_registration_is_still_registered_after_a_wake() {
    // thaw_registration books the refresh (registration.rs) and leaves the
    // account Restored. A resume is the ordinary thing to happen next on the
    // machine that just woke, and the ladder must not leave the account with
    // nothing scheduled and nothing sent.
    let t0 = Instant::now();
    let mut before = agent(t0);
    let first = before.add_account(account());
    before.register(first, t0).expect("a REGISTER");
    let request = transmits(&mut before)
        .into_iter()
        .next()
        .expect("the REGISTER");
    deliver(&mut before, &granted(&request, 3_600), t0);
    let snapshot = before
        .freeze_registration(first, t0)
        .expect("a binding worth writing down");

    let mut woken = agent(t0);
    let id = woken.add_account(account());
    woken
        .thaw_registration(id, &snapshot, Duration::from_secs(60), t0)
        .expect("a snapshot this build wrote");
    assert_eq!(
        woken.registration_state(id),
        Some(RegistrationState::Restored)
    );
    assert!(woken.poll_timeout().is_some(), "the refresh was booked");
    drop_events(&mut woken);

    woken.resumed(t0);
    let out = transmits(&mut woken);
    let mut at = t0;
    for _ in 0..8 {
        at += Duration::from_secs(64);
        woken.handle_timeout(at);
    }
    let later = transmits(&mut woken);
    assert!(
        out.iter()
            .chain(later.iter())
            .any(|bytes| bytes.starts_with(b"REGISTER ")),
        "a restored binding met a wake and nothing ever registered it again"
    );
}

/// What the ladder left of it.
#[test]
fn a_restored_registration_survives_a_network_change_with_something_scheduled() {
    let t0 = Instant::now();
    let mut before = agent(t0);
    let first = before.add_account(account());
    before.register(first, t0).expect("a REGISTER");
    let request = transmits(&mut before)
        .into_iter()
        .next()
        .expect("the REGISTER");
    deliver(&mut before, &granted(&request, 3_600), t0);
    let snapshot = before.freeze_registration(first, t0).expect("a binding");

    let mut woken = agent(t0);
    let id = woken.add_account(account());
    woken
        .thaw_registration(id, &snapshot, Duration::from_secs(60), t0)
        .expect("a snapshot this build wrote");
    drop_events(&mut woken);

    // any of the four entry points does it; this is the one a phone that
    // changes access point calls
    let from = crate::lifecycle::Network::new(crate::lifecycle::Link::Wifi)
        .address("192.0.2.1".parse().expect("an address"))
        .interface("en0");
    let to = crate::lifecycle::Network::new(crate::lifecycle::Link::Cellular)
        .address("192.0.2.1".parse().expect("an address"))
        .interface("en0");
    woken.network_changed(&from, &to, t0);
    let _ = transmits(&mut woken);
    drop_events(&mut woken);

    assert!(
        woken.poll_timeout().is_some(),
        "the account is {:?} with nothing scheduled and nothing sent",
        woken.registration_state(id)
    );
}

// -- 2. suspension must stop a subscription's own timers too -----------------

#[test]
fn a_suspended_stack_with_a_subscription_has_no_deadline_left_to_fire() {
    // lifecycle.rs: "nothing stays scheduled, so a stack that is suspended and
    // never resumed has no deadline to fire and no work to leave behind" —
    // asserted here against thirty subscriptions rather than one, because
    // poll_timeout() takes the min over every one of them and a single
    // un-cleared deadline is enough to fail it.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("a REGISTER");
    let request = transmits(&mut agent)
        .into_iter()
        .next()
        .expect("the REGISTER");
    deliver(&mut agent, &granted(&request, 3_600), t0);
    let mut subscribes = Vec::with_capacity(30);
    for n in 0..30 {
        agent
            .subscribe(
                id,
                &Subscribe::new(uri(&format!("sip:user{n}@example.com")), "dialog"),
                t0,
            )
            .expect("a subscription");
        subscribes.push(
            transmits(&mut agent)
                .into_iter()
                .next()
                .expect("the SUBSCRIBE"),
        );
    }
    drop_events(&mut agent);
    // a lamp cannot be demoted from believing something it was never told, so
    // every one is brought to `Active` first: the direct answer §3.1.1 makes
    // mandatory, then the NOTIFY that actually grants it (§4.1.3)
    for (n, subscribe) in subscribes.iter().enumerate() {
        deliver(&mut agent, &subscribed(subscribe, 3_600), t0);
        deliver(
            &mut agent,
            &notify(subscribe, 1, &format!("nfy{n}"), "active"),
            t0,
        );
    }
    let _ = transmits(&mut agent);
    drop_events(&mut agent);

    // past Timer F for the SUBSCRIBEs and Timer J for the NOTIFYs this end
    // answered (64*T1 each, unreliable transport), so nothing of the
    // endpoint's own transaction bookkeeping is left to explain a deadline
    let settled = t0 + Duration::from_secs(40);
    agent.handle_timeout(settled);
    let _ = transmits(&mut agent);
    drop_events(&mut agent);

    agent.suspending(settled);
    assert_eq!(
        agent.poll_timeout(),
        None,
        "a suspended stack still has a deadline to fire"
    );
}

#[test]
fn a_resumed_stack_resubscribes_everything_it_demoted_on_the_way_out() {
    // The twin of the test above: distrust() clearing a subscription's timers
    // is only half of it, because nothing else re-arms them. Without a
    // resubscribe wired into the ladder, thirty demoted subscriptions each
    // wait out whatever was left of their own, now-stale, refresh schedule —
    // this proves the ladder does it instead, for all thirty, not just one.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("a REGISTER");
    let request = transmits(&mut agent)
        .into_iter()
        .next()
        .expect("the REGISTER");
    deliver(&mut agent, &granted(&request, 3_600), t0);
    let mut handles = Vec::with_capacity(30);
    let mut subscribes = Vec::with_capacity(30);
    for n in 0..30 {
        handles.push(
            agent
                .subscribe(
                    id,
                    &Subscribe::new(uri(&format!("sip:user{n}@example.com")), "dialog"),
                    t0,
                )
                .expect("a subscription"),
        );
        subscribes.push(
            transmits(&mut agent)
                .into_iter()
                .next()
                .expect("the SUBSCRIBE"),
        );
    }
    drop_events(&mut agent);
    for (n, subscribe) in subscribes.iter().enumerate() {
        deliver(&mut agent, &subscribed(subscribe, 3_600), t0);
        deliver(
            &mut agent,
            &notify(subscribe, 1, &format!("nfy{n}"), "active"),
            t0,
        );
    }
    let _ = transmits(&mut agent);
    drop_events(&mut agent);

    agent.suspending(t0);
    // Distrust and Reregister both run synchronously inside resumed(): the
    // first rung sends nothing and always waits zero, so the ladder reaches
    // Reregister before this call returns. A tick loop here would only add
    // the Timer N retries of the fresh SUBSCRIBEs this already sent, since
    // nothing answers them — that noise is not what this test is asking.
    agent.resumed(t0);
    let out = transmits(&mut agent);

    let before: Vec<Vec<u8>> = subscribes
        .iter()
        .map(|bytes| header_of(bytes, b"Call-ID:"))
        .collect();
    let subscribes = out
        .iter()
        .filter(|bytes| bytes.starts_with(b"SUBSCRIBE "))
        .count();
    assert_eq!(
        subscribes,
        30,
        "a wake left {} of 30 subscriptions without a fresh SUBSCRIBE",
        30_usize.saturating_sub(subscribes)
    );
    for handle in handles {
        assert!(
            agent.subscription_state(handle).is_some(),
            "a demoted subscription went silently dead instead of being resubscribed"
        );
    }

    // and each of the thirty is a new subscription rather than the old one
    // said again. §4.1.2.4 identifies a subscription by the dialog its
    // Call-ID and tags name; re-using them would offer the notifier a second
    // subscription under a name it already holds one for, and leave it to
    // decide which of the two the next NOTIFY belongs to.
    let fresh: Vec<Vec<u8>> = out
        .iter()
        .filter(|bytes| bytes.starts_with(b"SUBSCRIBE "))
        .map(|bytes| header_of(bytes, b"Call-ID:"))
        .collect();
    for call_id in &fresh {
        assert!(
            !before.contains(call_id),
            "the wake re-subscribed under a Call-ID the notifier already has a \
             dialog for: {}",
            String::from_utf8_lossy(call_id)
        );
    }
    let mut seen = fresh.clone();
    seen.sort();
    seen.dedup();
    assert_eq!(
        seen.len(),
        30,
        "thirty subscriptions went out under fewer than thirty names"
    );
}

/// One header's value, as bytes, for a test that cares which one it is.
fn header_of(message: &[u8], name: &[u8]) -> Vec<u8> {
    message
        .split(|byte| *byte == b'\n')
        .find(|line| line.starts_with(name))
        .map(|line| {
            line.get(name.len()..)
                .unwrap_or_default()
                .iter()
                .copied()
                .filter(|byte| !byte.is_ascii_whitespace())
                .collect()
        })
        .unwrap_or_default()
}

// -- 3. a push after a wake must send REGISTER --------------------------------

#[test]
fn a_push_after_a_wake_sends_the_binding_refresh_rfc_8599_makes_a_must() {
    // announce.rs: "The binding is refreshed at once, on whatever path exists
    // -- RFC 8599 4.1.3 makes that a MUST for a woken UA". The clock does not
    // advance while a machine is suspended, so every transaction the endpoint
    // held before the sleep is still running when it wakes -- including the
    // REGISTER whose 200 arrived a moment before it.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("a REGISTER");
    let request = transmits(&mut agent)
        .into_iter()
        .next()
        .expect("the REGISTER");
    deliver(&mut agent, &granted(&request, 3_600), t0);
    drop_events(&mut agent);

    // the lid closes, and opens again four milliseconds of monotonic time later
    agent.suspending(t0);
    let woke = t0 + Duration::from_millis(4);
    agent
        .announce(id, uri("sip:bob@example.com"), woke)
        .expect("the push");
    let out = transmits(&mut agent);
    assert!(
        out.iter().any(|bytes| bytes.starts_with(b"REGISTER ")),
        "the push was answered with nothing on the wire: {out:?}"
    );
}

/// Which of `refresh_binding`'s two early returns swallowed it.
#[test]
fn the_pre_warm_is_swallowed_by_a_transaction_the_sleep_left_behind() {
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent.register(id, t0).expect("a REGISTER");
    let request = transmits(&mut agent)
        .into_iter()
        .next()
        .expect("the REGISTER");
    deliver(&mut agent, &granted(&request, 3_600), t0);
    drop_events(&mut agent);
    agent.suspending(t0);

    let reg = agent.registrations.get(&id).expect("a registration");
    assert_eq!(
        reg.state,
        RegistrationState::Unverified,
        "not the Failed early return"
    );
    assert_eq!(
        reg.transaction, None,
        "the REGISTER whose 200 already arrived still reads as in flight"
    );
}

// -- 4. a session timer pre-armed across a 422, before any dialog exists -----

#[test]
fn a_session_timer_that_cannot_refresh_moves_off_the_instant_it_fired() {
    // on_session_too_brief (RFC 4028 §7.3) arms a session timer -- with a
    // `due` of its own -- the moment a 422 comes back to the initial INVITE,
    // to have one ready for whenever the eventual 2xx settles it for real.
    // Nothing about that retried INVITE is confirmed yet, and until a
    // provisional response gives it a dialog, it has none either.
    // fire_session_timers picks every call whose timer is due, and
    // send_refresh (timers.rs) used to return without touching `due` on
    // exactly those two grounds: no dialog to refresh in, or not confirmed.
    // A deadline in the past that nothing moves is a deadline poll_timeout
    // keeps handing back, which is an event loop that never sleeps.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
        .expect("the INVITE goes");
    let invite = transmits(&mut agent)
        .into_iter()
        .next()
        .expect("the INVITE");
    deliver(
        &mut agent,
        &reply(
            &invite,
            422,
            "Session Interval Too Small",
            "Min-SE: 120\r\n",
        ),
        t0,
    );
    let retry = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the retried INVITE, asked again per RFC 4028 §7.3");
    drop_events(&mut agent);

    // one 180 is enough to take the retry's own transaction out of the state
    // Timer B could still end it from, so what is left running down is the
    // session timer and nothing else -- and then the far end goes silent
    let mut ringing = b"SIP/2.0 180 Ringing\r\n".to_vec();
    for (name, value) in [
        ("Via", header(&retry, HeaderName::Via)),
        ("From", header(&retry, HeaderName::From)),
        (
            "To",
            format!("{};tag=desk", text(&retry, HeaderName::To)).into_bytes(),
        ),
        ("Call-ID", header(&retry, HeaderName::CallId)),
        ("CSeq", header(&retry, HeaderName::CSeq)),
    ] {
        ringing.extend_from_slice(name.as_bytes());
        ringing.extend_from_slice(b": ");
        ringing.extend_from_slice(&value);
        ringing.extend_from_slice(b"\r\n");
    }
    ringing.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    deliver(&mut agent, &ringing, t0);
    let _ = transmits(&mut agent);
    drop_events(&mut agent);

    // Min-SE: 120 floors the retried interval at 120s, so the timer this end
    // pre-armed as the (still hypothetical) refresher comes due at half that
    let due = t0 + Duration::from_secs(60);
    agent.handle_timeout(due);
    let _ = transmits(&mut agent);
    drop_events(&mut agent);

    assert!(
        agent.poll_timeout().is_none_or(|at| at > due),
        "the timer is still due at the instant that already fired: the loop spins"
    );
}

// -- 5. a session timer pre-armed across a 422, with an early dialog already
//       open but nothing confirmed yet -----------------------------------

#[test]
fn a_session_timer_with_a_dialog_but_not_confirmed_moves_off_the_instant_it_fired() {
    // The other early return in send_refresh with the same shape as the one
    // above: the retry's tagged 180 this time also names a Contact, so it
    // opens a real early dialog instead of being dropped for naming no
    // remote target. `state.dialog` is `Some`, but nothing is confirmed --
    // no 2xx has arrived -- so fire_session_timers reaches the *other*
    // ground send_refresh (timers.rs) used to return from without touching
    // `due`. Same past deadline, same spinning loop.
    let t0 = Instant::now();
    let mut agent = agent(t0);
    let id = agent.add_account(account());
    agent
        .call(id, &OutgoingCall::new(uri("sip:bob@example.com")), t0)
        .expect("the INVITE goes");
    let invite = transmits(&mut agent)
        .into_iter()
        .next()
        .expect("the INVITE");
    deliver(
        &mut agent,
        &reply(
            &invite,
            422,
            "Session Interval Too Small",
            "Min-SE: 120\r\n",
        ),
        t0,
    );
    let retry = transmits(&mut agent)
        .into_iter()
        .find(|bytes| bytes.starts_with(b"INVITE "))
        .expect("the retried INVITE, asked again per RFC 4028 §7.3");
    drop_events(&mut agent);

    let mut ringing = b"SIP/2.0 180 Ringing\r\n".to_vec();
    for (name, value) in [
        ("Via", header(&retry, HeaderName::Via)),
        ("From", header(&retry, HeaderName::From)),
        (
            "To",
            format!("{};tag=desk", text(&retry, HeaderName::To)).into_bytes(),
        ),
        ("Call-ID", header(&retry, HeaderName::CallId)),
        ("CSeq", header(&retry, HeaderName::CSeq)),
    ] {
        ringing.extend_from_slice(name.as_bytes());
        ringing.extend_from_slice(b": ");
        ringing.extend_from_slice(&value);
        ringing.extend_from_slice(b"\r\n");
    }
    ringing.extend_from_slice(b"Contact: <sip:bob@192.0.2.9>\r\n");
    ringing.extend_from_slice(b"Content-Length: 0\r\n\r\n");
    deliver(&mut agent, &ringing, t0);
    let _ = transmits(&mut agent);
    drop_events(&mut agent);

    // Min-SE: 120 floors the retried interval at 120s, so the timer this end
    // pre-armed as the (still hypothetical) refresher comes due at half that
    let due = t0 + Duration::from_secs(60);
    agent.handle_timeout(due);
    let _ = transmits(&mut agent);
    drop_events(&mut agent);

    assert!(
        agent.poll_timeout().is_none_or(|at| at > due),
        "the timer is still due at the instant that already fired: the loop spins"
    );
}
