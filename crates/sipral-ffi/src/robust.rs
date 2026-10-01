// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! The failures a softphone meets in the field, each written down as the
//! guarantee that answers it.
//!
//! Every test here is one line of the table in `docs/11-testing.md`, "What a
//! field failure is answered by": a call from a thread nothing registered, a
//! subscription asked for before its account has done anything, a feature
//! this build lacks, text with neither a length nor a terminator, a storm of
//! INVITEs at one line, a connection that takes a request and never answers,
//! the millisecond an event is raised at, and a CANCEL asked for before
//! anything came back. What needs a real network to show — a datagram broken
//! into fragments, a connection whose path goes dark — is in `scripts/lab.sh
//! robust`; what is here needs none.

use std::ffi::{CStr, c_char, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::abi::SURFACE;
use crate::account::{sipral_account_add, sipral_account_register, sipral_account_remove};
use crate::call::tests::{
    account_on, answered_with, as_text, call_config, deliver, invitation, place, ringing, sent,
};
use crate::call::{sipral_call_hangup, sipral_call_reject, sipral_call_state};
use crate::capabilities::{
    SIPRAL_FEATURE_AUDIO_DEVICE, SIPRAL_FEATURE_DTLS_SRTP, SIPRAL_FEATURE_ICE, SIPRAL_FEATURE_STUN,
    SIPRAL_FEATURE_TURN_STREAM, SipralCapabilities, sipral_capabilities,
};
use crate::error::last_error_text;
use crate::event::{SipralCallEndReason, SipralCallState, SipralEvent, SipralEventKind};
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::stack::tests::{Observed, config, create, poll, poll_result, record};
use crate::stack::{SipralStackConfig, SipralTransport, sipral_stack_destroy, sipral_stack_poll};
use crate::status::{SipralStatus, sipral_status_name};
use crate::subscription::{SipralSubscribeConfig, sipral_account_subscribe};
use crate::transport::{SIPRAL_TRANSPORT_MAIN, sipral_stack_receive_datagram};

/// What one call event said, copied out inside the callback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Said {
    kind: SipralEventKind,
    call: SipralHandle,
    state: u32,
    end_reason: u32,
    status_code: u32,
}

/// Every event a stack of these tests raised, in order.
#[derive(Default)]
struct Heard {
    all: Vec<Said>,
}

impl Heard {
    fn of(&self, call: SipralHandle) -> Vec<Said> {
        self.all
            .iter()
            .filter(|said| said.call == call)
            .copied()
            .collect()
    }

    fn kinds(&self) -> Vec<SipralEventKind> {
        self.all.iter().map(|said| said.kind).collect()
    }
}

unsafe extern "C" fn hear(event: *const SipralEvent, user_data: *mut c_void) {
    let heard = unsafe { &mut *user_data.cast::<Heard>() };
    let event = unsafe { &*event };
    let (state, end_reason, status_code) = match event.kind {
        SipralEventKind::RegistrationChanged
        | SipralEventKind::SubscriptionChanged
        | SipralEventKind::Notified
        | SipralEventKind::StunServer
        | SipralEventKind::NatMapping
        | SipralEventKind::TransportWanted => (0, 0, 0),
        _ => {
            let call = unsafe { event.payload.call };
            (call.state, call.end_reason, call.status_code)
        }
    };
    heard.all.push(Said {
        kind: event.kind,
        call: event.call,
        state,
        end_reason,
        status_code,
    });
}

/// A stack whose events land in `heard`, speaking `transport`.
fn stack_hearing(heard: &mut Heard, transport: SipralTransport) -> SipralHandle {
    let mut unused = Observed::default();
    let mut settings = config(record, &mut unused);
    settings.event_callback = Some(hear);
    settings.event_user_data = ptr::from_mut(heard).cast::<c_void>();
    settings.transport = transport as u32;
    let (status, stack) = create(&settings);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    stack
}

fn state_of(stack: SipralHandle, call: SipralHandle) -> u32 {
    let mut state = u32::MAX;
    let status = unsafe { sipral_call_state(stack, call, &raw mut state) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    state
}

fn start_line(message: &[u8]) -> String {
    String::from_utf8_lossy(message)
        .split("\r\n")
        .next()
        .unwrap_or_default()
        .to_owned()
}

// -- a call from any thread ----------------------------------------------

/// What a thread may be answered, whatever it asked and whenever: every
/// status this surface has for a call that could not be done now, and none
/// that says the library broke. `Panic` is not among them — a caught panic
/// is still a bug, and this is the test that would find one. `LimitReached`
/// is: the workers place calls faster than they hang them up, and past
/// `max_dialogs` a call placed is refused before anything is sent. So is
/// `ClockBehind`: eight threads reading one clock and racing for the stack
/// hand it readings more than the slack apart when the machine is loaded.
const TOLERATED: &[SipralStatus] = &[
    SipralStatus::Ok,
    SipralStatus::Busy,
    SipralStatus::InvalidHandle,
    SipralStatus::StaleHandle,
    SipralStatus::WrongState,
    SipralStatus::InvalidArgument,
    SipralStatus::NotSent,
    SipralStatus::Exhausted,
    SipralStatus::LimitReached,
    SipralStatus::ClockBehind,
];

/// A stack that asserts on a thread it was not told about brings the whole
/// application down from any thread a platform happens to call back on;
/// there is no such thing here, and this is the proof under load: eight
/// threads nobody registered,
/// each calling a mix of entry points on one stack as fast as they can —
/// polling it, adding and removing accounts, placing and hanging up calls,
/// handing in datagrams whole and broken, subscribing — while the stack is
/// destroyed under them halfway through. Every call is answered with a
/// status, none of them `SIPRAL_STATUS_PANIC`, and every call after the
/// destroy is refused as a handle that names nothing.
#[test]
fn threads_nobody_registered_calling_under_load_get_a_status_never_a_crash() {
    /// How many calls each worker makes once the destroy has returned.
    const AFTER_DESTROY: usize = 32;
    let mut observed = Observed::default();
    let (stack, account) = crate::call::tests::media_line(&mut observed, |_| {});
    let destroyed = Arc::new(AtomicBool::new(false));
    let clock = Arc::new(Instant::now());
    let mut workers = Vec::new();
    for worker in 0..8_u64 {
        let destroyed = Arc::clone(&destroyed);
        let clock = Arc::clone(&clock);
        workers.push(thread::spawn(move || {
            let mut answered: Vec<(u64, SipralStatus)> = Vec::new();
            let mut after_destroy = Vec::new();
            let mut round = 0_u64;
            let started = Instant::now();
            // a second and a half at the least, and then on until some calls
            // have been made after the destroy returned, however long a
            // loaded machine keeps the destroy waiting for its turn
            while started.elapsed() < Duration::from_millis(1_500)
                || (after_destroy.len() < AFTER_DESTROY
                    && started.elapsed() < Duration::from_secs(30))
            {
                round += 1;
                let gone = destroyed.load(Ordering::SeqCst);
                let now = u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX);
                let status = one_call(stack, account, worker, round, now);
                if gone {
                    after_destroy.push(status);
                }
                answered.push((round, status));
            }
            (answered, after_destroy)
        }));
    }
    thread::sleep(Duration::from_millis(700));
    let destroy = unsafe { sipral_stack_destroy(stack) };
    assert!(
        destroy == SipralStatus::Ok || destroy == SipralStatus::Busy,
        "{destroy:?}"
    );
    if destroy == SipralStatus::Busy {
        // a worker was inside; the stack is asked again until it is free
        let mut again = SipralStatus::Busy;
        while again == SipralStatus::Busy {
            again = unsafe { sipral_stack_destroy(stack) };
        }
        assert_eq!(again, SipralStatus::Ok);
    }
    // only once the destroy has returned: a call that began before that
    // could still find the stack there, and answered as it would any other
    // time, however many of them a loaded machine fits in before the destroy
    // gets its turn
    destroyed.store(true, Ordering::SeqCst);
    let mut calls = 0_usize;
    for worker in workers {
        let (answered, after) = worker.join().expect("no thread died");
        calls += answered.len();
        for (round, status) in answered {
            assert!(
                TOLERATED.contains(&status),
                "round {round} was answered {status:?}: {}",
                last_error_text()
            );
        }
        // every call that began after the destroy returned names a stack
        // that is gone
        assert!(
            after.len() >= AFTER_DESTROY,
            "a worker made {} calls after the destroy",
            after.len()
        );
        let refused = after.iter().all(|status| {
            matches!(
                status,
                SipralStatus::InvalidHandle | SipralStatus::StaleHandle
            )
        });
        assert!(refused, "a destroyed stack answered {after:?}");
    }
    assert!(calls > 1_000, "the threads made {calls} calls between them");
}

/// One call of the mix, chosen by the worker and the round.
fn one_call(
    stack: SipralHandle,
    account: SipralHandle,
    worker: u64,
    round: u64,
    now: u64,
) -> SipralStatus {
    match (worker + round) % 7 {
        0 => unsafe { sipral_stack_poll(stack, now, ptr::null_mut()) },
        1 => {
            let settings = crate::account::tests::account_config();
            let mut added = SIPRAL_HANDLE_NONE;
            let status =
                unsafe { sipral_account_add(stack, ptr::from_ref(&settings), &raw mut added) };
            if status == SipralStatus::Ok {
                unsafe { sipral_account_remove(stack, added) }
            } else {
                status
            }
        }
        2 => {
            let (status, call) = place(stack, account, &call_config(), now);
            if status == SipralStatus::Ok {
                unsafe { sipral_call_hangup(stack, call, now) }
            } else {
                status
            }
        }
        3 => {
            let broken = b"INVITE sip:alice@192.0.2.10 SIP/2.0\r\nVia: nonsense\r\n\r\n";
            let whole = invitation();
            let data: &[u8] = if round.is_multiple_of(2) {
                broken
            } else {
                &whole
            };
            let from = "203.0.113.5:5060";
            unsafe {
                sipral_stack_receive_datagram(
                    stack,
                    SIPRAL_TRANSPORT_MAIN,
                    data.as_ptr(),
                    data.len(),
                    from.as_ptr().cast::<c_char>(),
                    from.len(),
                    ptr::null(),
                    0,
                    now,
                )
            }
        }
        4 => {
            let target = "sip:2001@example.com";
            let package = "dialog";
            let settings = SipralSubscribeConfig {
                reserved: 0,
                size: size_of::<SipralSubscribeConfig>(),
                target: target.as_ptr().cast::<c_char>(),
                target_len: target.len(),
                package: package.as_ptr().cast::<c_char>(),
                package_len: package.len(),
                accept: ptr::null(),
                accept_len: 0,
                expires_seconds: 0,
                destination: ptr::null(),
                destination_len: 0,
                transport: 0,
            };
            let mut subscription = SIPRAL_HANDLE_NONE;
            unsafe {
                sipral_account_subscribe(
                    stack,
                    account,
                    ptr::from_ref(&settings),
                    &raw mut subscription,
                    now,
                )
            }
        }
        5 => {
            // a handle that was never a call on this stack
            unsafe { sipral_call_reject(stack, account, 486, now) }
        }
        _ => unsafe { sipral_account_register(stack, account, now) },
    }
}

// -- a subscription before anything else ---------------------------------

fn subscribe(stack: SipralHandle, account: SipralHandle, now: u64) -> (SipralStatus, SipralHandle) {
    let target = "sip:2001@example.com";
    let package = "dialog";
    let settings = SipralSubscribeConfig {
        reserved: 0,
        size: size_of::<SipralSubscribeConfig>(),
        target: target.as_ptr().cast::<c_char>(),
        target_len: target.len(),
        package: package.as_ptr().cast::<c_char>(),
        package_len: package.len(),
        accept: ptr::null(),
        accept_len: 0,
        expires_seconds: 0,
        destination: ptr::null(),
        destination_len: 0,
        transport: 0,
    };
    let mut subscription = SIPRAL_HANDLE_NONE;
    let status = unsafe {
        sipral_account_subscribe(
            stack,
            account,
            ptr::from_ref(&settings),
            &raw mut subscription,
            now,
        )
    };
    (status, subscription)
}

/// The busy lamp field asked for in the same breath as the account is
/// added, before the account has registered or sent anything: a SUBSCRIBE
/// goes, and the subscription says where it stands as an event.
#[test]
fn a_subscription_asked_for_the_moment_its_account_exists_goes_and_is_reported() {
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, SipralTransport::Udp);
    let account = account_on(stack);
    let (status, subscription) = subscribe(stack, account, 10);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_ne!(subscription, SIPRAL_HANDLE_NONE);
    let out = sent(stack);
    assert!(
        out.iter().any(|message| message.starts_with(b"SUBSCRIBE ")),
        "{:?}",
        out.iter()
            .map(|message| start_line(message))
            .collect::<Vec<_>>()
    );
    let _ = poll(stack, 10);
    assert!(
        heard
            .kinds()
            .contains(&SipralEventKind::SubscriptionChanged),
        "{:?}",
        heard.kinds()
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// The same on a connection that has closed: nothing can leave, and the
/// application is told so — refused where it asked, or an event — rather
/// than left with a subscription that silently never went.
#[test]
fn a_subscription_on_a_transport_that_has_died_is_told_never_a_crash() {
    for protocol in [SipralTransport::Tcp, SipralTransport::Tls] {
        let mut heard = Heard::default();
        let stack = stack_hearing(&mut heard, protocol);
        let account = account_on(stack);
        assert_eq!(
            unsafe {
                crate::transport::sipral_stack_stream_closed(stack, SIPRAL_TRANSPORT_MAIN, 5)
            },
            SipralStatus::Ok
        );
        let (status, subscription) = subscribe(stack, account, 10);
        let _ = poll(stack, 10);
        let told_by_event = heard.kinds().iter().any(|kind| {
            matches!(
                kind,
                SipralEventKind::TransportWanted | SipralEventKind::SubscriptionChanged
            )
        });
        assert!(
            status != SipralStatus::Ok || told_by_event,
            "{protocol:?}: answered {status:?} and said nothing: {:?}",
            heard.kinds()
        );
        if status == SipralStatus::Ok {
            assert_ne!(subscription, SIPRAL_HANDLE_NONE);
        } else {
            assert!(TOLERATED.contains(&status), "{protocol:?}: {status:?}");
            assert!(!last_error_text().is_empty(), "a refusal says why");
        }
        // the stack is still whole: time passes and it is polled as usual
        let _ = poll(stack, 40_000);
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }
}

// -- nothing a build lacks is taken in silence -------------------------------

/// A setting that asks a stack for one optional feature.
type Ask = fn(&mut SipralStackConfig);

/// For every optional feature: the setting that asks for it, applied to a
/// stack configuration. Each bit clear in `sipral_capabilities` must make
/// its setting `SIPRAL_STATUS_NOT_SUPPORTED`; each bit set must make it
/// something other than that. Run in the default build and in the one
/// without default features, which `scripts/check.sh` runs both of, so both
/// halves of every line are exercised somewhere.
#[test]
fn every_feature_this_build_lacks_is_refused_where_it_is_asked_for_never_ignored() {
    let mut capabilities = SipralCapabilities {
        size: size_of::<SipralCapabilities>(),
        codec_count: 0,
        transports: 0,
        features: 0,
    };
    assert_eq!(
        unsafe { sipral_capabilities(&raw mut capabilities) },
        SipralStatus::Ok
    );
    let asks: [(u32, &str, Ask); 5] = [
        (SIPRAL_FEATURE_STUN, "SIPRAL_NAT_STUN", |settings| {
            settings.nat = 2;
            (settings.stun_server, settings.stun_server_len) = as_text("198.51.100.1:3478");
        }),
        (SIPRAL_FEATURE_ICE, "SIPRAL_ICE_OFFERED", |settings| {
            settings.ice = 2;
        }),
        (SIPRAL_FEATURE_DTLS_SRTP, "SIPRAL_SRTP_DTLS", |settings| {
            settings.srtp = 4;
        }),
        (
            SIPRAL_FEATURE_TURN_STREAM,
            "turn_transport TCP",
            |settings| {
                settings.nat = 2;
                (settings.stun_server, settings.stun_server_len) = as_text("198.51.100.1:3478");
                (settings.turn_server, settings.turn_server_len) = as_text("198.51.100.1:3478");
                (settings.turn_username, settings.turn_username_len) = as_text("user");
                (settings.turn_password, settings.turn_password_len) = as_text("secret");
                settings.turn_transport = 2;
            },
        ),
        (
            SIPRAL_FEATURE_AUDIO_DEVICE,
            "SIPRAL_AUDIO_DEVICE",
            |settings| {
                settings.audio = 2;
            },
        ),
    ];
    for (bit, name, ask) in asks {
        let mut observed = Observed::default();
        let mut settings = config(record, &mut observed);
        ask(&mut settings);
        let (status, stack) = create(&settings);
        if capabilities.features & bit == 0 {
            assert_eq!(
                status,
                SipralStatus::NotSupported,
                "{name}: the build lacks it and it was answered {status:?}: {}",
                last_error_text()
            );
        } else {
            assert_ne!(
                status,
                SipralStatus::NotSupported,
                "{name}: the build has it and refused it as missing"
            );
        }
        if status == SipralStatus::Ok {
            assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
        }
    }
}

// -- text across the boundary -------------------------------------------------

/// The pointer types that carry text or bytes across the boundary.
const TEXT_TYPES: &[&str] = &["*constc_char", "*mutc_char", "*constu8", "*mutu8"];

/// A type as the declaration spelled it, with the spacing the tokens came
/// with taken out.
fn spelled(rust_type: &str) -> String {
    rust_type
        .chars()
        .filter(|letter| !letter.is_whitespace())
        .collect()
}

/// Whether `member`, beside the members in `all`, has its length there: the
/// member named `<member>_len`, or one of the two ways an output buffer
/// says how much room it has.
fn has_length(member: &str, all: &[&str]) -> bool {
    let named = |suffix: &str| all.contains(&format!("{member}{suffix}").as_str());
    named("_len")
        || named("_capacity")
        || (member == "data" && (all.contains(&"capacity") || all.contains(&"len")))
        || (member == "buffer" && all.contains(&"capacity"))
}

/// No text crosses in either direction without a length beside it, so that
/// nothing on either side ever has to find where a string ends by looking for
/// a NUL that may not be there. Walked over the whole declared surface: every
/// text pointer a function takes and every one a record carries has its
/// length; the only text handed out without one is the handful of static
/// names, and each of those is NUL-terminated, every value checked.
#[test]
fn no_text_crosses_the_boundary_without_its_length_or_a_terminator() {
    let mut unmeasured = Vec::new();
    for function in SURFACE.functions {
        let names: Vec<&str> = function
            .parameters
            .iter()
            .map(|member| member.name)
            .collect();
        for member in function.parameters {
            if TEXT_TYPES.contains(&spelled(member.rust_type).as_str())
                && !has_length(member.name, &names)
            {
                unmeasured.push(format!("{}({})", function.name, member.name));
            }
        }
    }
    for record in SURFACE.records {
        let names: Vec<&str> = record.fields.iter().map(|member| member.name).collect();
        for member in record.fields {
            if TEXT_TYPES.contains(&spelled(member.rust_type).as_str())
                && !has_length(member.name, &names)
            {
                unmeasured.push(format!("{}::{}", record.name, member.name));
            }
        }
    }
    assert!(
        unmeasured.is_empty(),
        "text with no length beside it: {unmeasured:?}"
    );

    // what is handed out with no length: the functions returning a pointer
    let mut returning: Vec<&str> = SURFACE
        .functions
        .iter()
        .filter(|function| spelled(function.returns) == "*constc_char")
        .map(|function| function.name)
        .collect();
    returning.sort_unstable();
    assert_eq!(
        returning,
        vec![
            "sipral_codec_name",
            "sipral_event_kind_name",
            "sipral_status_name"
        ],
        "a new function hands out text with no length: check it is a static, terminated name"
    );
    for status in -2..40 {
        let name = unsafe { sipral_status_name(status) };
        if !name.is_null() {
            let text = unsafe { CStr::from_ptr(name) };
            assert!(!text.to_bytes().is_empty() && text.to_str().is_ok());
        }
    }
    for kind in 0..100 {
        let name = unsafe { crate::event::sipral_event_kind_name(kind) };
        if !name.is_null() {
            let text = unsafe { CStr::from_ptr(name) };
            assert!(!text.to_bytes().is_empty() && text.to_str().is_ok());
        }
    }
    for codec in 0..32 {
        let name = unsafe { crate::media::sipral_codec_name(codec) };
        if !name.is_null() {
            let text = unsafe { CStr::from_ptr(name) };
            assert!(!text.to_bytes().is_empty() && text.to_str().is_ok());
        }
    }
}

/// The input half, read the way it is written: a buffer with no NUL in it
/// and garbage after its length is read for exactly its length.
#[test]
fn text_handed_in_is_read_for_its_length_and_not_to_a_nul() {
    let mut observed = Observed::default();
    let stack = crate::stack::tests::stack(&mut observed);
    // the target, then bytes that are no part of it and no NUL anywhere
    let mut buffer = b"sip:2001@example.com".to_vec();
    let length = buffer.len();
    buffer.extend_from_slice(b">>>not part of it<<<");
    let account = account_on(stack);
    let package = "dialog";
    let settings = SipralSubscribeConfig {
        reserved: 0,
        size: size_of::<SipralSubscribeConfig>(),
        target: buffer.as_ptr().cast::<c_char>(),
        target_len: length,
        package: package.as_ptr().cast::<c_char>(),
        package_len: package.len(),
        accept: ptr::null(),
        accept_len: 0,
        expires_seconds: 0,
        destination: ptr::null(),
        destination_len: 0,
        transport: 0,
    };
    let mut subscription = SIPRAL_HANDLE_NONE;
    let status = unsafe {
        sipral_account_subscribe(
            stack,
            account,
            ptr::from_ref(&settings),
            &raw mut subscription,
            10,
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let out = sent(stack);
    let subscribe = out
        .iter()
        .find(|message| message.starts_with(b"SUBSCRIBE "))
        .expect("a SUBSCRIBE");
    assert_eq!(
        start_line(subscribe),
        "SUBSCRIBE sip:2001@example.com SIP/2.0"
    );
    assert!(!String::from_utf8_lossy(subscribe).contains("not part of it"));
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

// -- a storm of INVITEs at one line -------------------------------------------

/// Call `n` of the storm: its own `Call-ID`, `From` tag and branch.
fn storm_invite(n: usize) -> Vec<u8> {
    String::from_utf8_lossy(&invitation())
        .replace("z9hG4bK-a-call-in", &format!("z9hG4bK-storm-{n}"))
        .replace("tag=farend", &format!("tag=storm-{n}"))
        .replace("a-call-in@203.0.113.5", &format!("storm-{n}@203.0.113.5"))
        .into_bytes()
}

/// Its CANCEL (RFC 3261 §9.1): the same branch, tag and `Call-ID`.
fn storm_cancel(n: usize) -> Vec<u8> {
    format!(
        "CANCEL sip:alice@192.0.2.10:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bK-storm-{n}\r\n\
Max-Forwards: 70\r\n\
From: <sip:bob@example.com>;tag=storm-{n}\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: storm-{n}@203.0.113.5\r\n\
CSeq: 1 CANCEL\r\n\
Content-Length: 0\r\n\r\n"
    )
    .into_bytes()
}

/// A hundred and twenty INVITEs at one line inside one millisecond, each
/// sent twice, from the one address a PBX sends from. With the rate floor
/// raised out of the way, every one is a call of its own; a CANCEL for every
/// third ends that call and no other, a refusal of one refuses that one, and
/// each response on the wire names its own call. With the floor where
/// `sipral_stack_create` leaves it, the calls past it are refused on the
/// wire and never become a handle, and the ones admitted are untouched.
#[test]
#[allow(clippy::too_many_lines)]
fn an_invite_storm_at_one_line_keeps_every_call_to_itself() {
    const CALLS: usize = 120;
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, SipralTransport::Udp);
    let _account = account_on(stack);
    assert_eq!(
        unsafe { crate::screening::sipral_stack_invite_limit(stack, 1, 10_000) },
        SipralStatus::Ok
    );
    for n in 0..CALLS {
        deliver(stack, &storm_invite(n), 1_000);
        deliver(stack, &storm_invite(n), 1_000);
    }
    let _ = poll(stack, 1_000);
    let _ = sent(stack);
    let incoming: Vec<SipralHandle> = heard
        .all
        .iter()
        .filter(|said| said.kind == SipralEventKind::IncomingCall)
        .map(|said| said.call)
        .collect();
    assert_eq!(
        incoming.len(),
        CALLS,
        "one call per INVITE, the retransmissions none"
    );
    let mut distinct = incoming.clone();
    distinct.sort_unstable();
    distinct.dedup();
    assert_eq!(distinct.len(), CALLS, "every call has a handle of its own");

    for n in (0..CALLS).step_by(3) {
        deliver(stack, &storm_cancel(n), 1_100);
    }
    assert_eq!(
        unsafe { sipral_call_reject(stack, incoming[1], 486, 1_100) },
        SipralStatus::Ok
    );
    let _ = poll(stack, 1_100);
    let out = sent(stack);
    for message in &out {
        let text = String::from_utf8_lossy(message);
        let call_id = text
            .split("\r\n")
            .find_map(|line| line.strip_prefix("Call-ID: "))
            .unwrap_or_default();
        let n: usize = call_id
            .strip_prefix("storm-")
            .and_then(|rest| rest.split('@').next())
            .and_then(|digits| digits.parse().ok())
            .expect("every response names a call of the storm");
        let line = start_line(message);
        if line.starts_with("SIP/2.0 486") {
            assert_eq!(n, 1, "the refusal went to call {n}");
        } else if line.starts_with("SIP/2.0 487") || line.contains("CANCEL") {
            assert_eq!(n % 3, 0, "call {n} was answered as cancelled: {line}");
        }
    }
    for (n, call) in incoming.iter().enumerate() {
        let ended: Vec<Said> = heard
            .of(*call)
            .into_iter()
            .filter(|said| said.kind == SipralEventKind::CallEnded)
            .collect();
        let expected = if n % 3 == 0 {
            Some(SipralCallEndReason::Cancelled as u32)
        } else if n == 1 {
            Some(SipralCallEndReason::LocalHangup as u32)
        } else {
            None
        };
        if let Some(reason) = expected {
            assert_eq!(ended.len(), 1, "call {n}: {ended:?}");
            if n % 3 == 0 {
                assert_eq!(ended[0].end_reason, reason, "call {n}");
            }
        } else {
            assert!(ended.is_empty(), "call {n} ended with another's: {ended:?}");
            assert_eq!(
                state_of(stack, *call),
                SipralCallState::Incoming as u32,
                "call {n}"
            );
        }
    }
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);

    // and at the floor a stack starts with
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, SipralTransport::Udp);
    let _account = account_on(stack);
    for n in 0..CALLS {
        deliver(stack, &storm_invite(n), 2_000);
    }
    let _ = poll(stack, 2_000);
    let admitted: Vec<SipralHandle> = heard
        .all
        .iter()
        .filter(|said| said.kind == SipralEventKind::IncomingCall)
        .map(|said| said.call)
        .collect();
    assert!(
        !admitted.is_empty() && admitted.len() < CALLS,
        "{} admitted",
        admitted.len()
    );
    let refused = sent(stack)
        .iter()
        .filter(|message| {
            let line = start_line(message);
            line.starts_with("SIP/2.0 4") || line.starts_with("SIP/2.0 5")
        })
        .count();
    assert_eq!(
        refused,
        CALLS - admitted.len(),
        "every INVITE past the floor is answered on the wire"
    );
    for call in &admitted {
        assert_eq!(state_of(stack, *call), SipralCallState::Incoming as u32);
    }
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

// -- a connection that takes a request and never answers -----------------

/// A server that accepts the connection and then says nothing, or a path
/// that goes dark after the handshake: the operating system keeps
/// retransmitting the segment for a quarter of an hour before it reports
/// anything, and a call that waits for it rings for a quarter of an hour.
/// Timer B (RFC 3261 §17.1.1.2) runs on a stream as on a datagram, and ends
/// the call at sixty-four times T1 — thirty-two seconds — with nothing from
/// the transport at all. The INVITE is written once: a stream retransmits
/// for itself.
#[test]
fn a_stream_that_takes_the_invite_and_never_answers_ends_the_call_at_timer_b() {
    for protocol in [SipralTransport::Tcp, SipralTransport::Tls] {
        let mut heard = Heard::default();
        let stack = stack_hearing(&mut heard, protocol);
        let account = account_on(stack);
        // the connection is open, to where the account's requests go: the
        // far end accepted it, and will say nothing on it
        let local = crate::stack::tests::BIND;
        let remote = "203.0.113.5:5060";
        let status = unsafe {
            crate::transport::sipral_stack_transport_bind(
                stack,
                SIPRAL_TRANSPORT_MAIN,
                0,
                local.as_ptr().cast::<c_char>(),
                local.len(),
                remote.as_ptr().cast::<c_char>(),
                remote.len(),
                900,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let (status, call) = place(stack, account, &call_config(), 1_000);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let mut written = 0;
        let mut now = 1_000;
        while now < 1_000 + 31_999 {
            let _ = poll(stack, now);
            written += sent(stack)
                .iter()
                .filter(|message| message.starts_with(b"INVITE "))
                .count();
            now += 250;
        }
        let _ = poll(stack, 1_000 + 31_999);
        assert!(
            heard
                .of(call)
                .iter()
                .all(|said| said.kind != SipralEventKind::CallEnded),
            "{protocol:?}: ended before Timer B"
        );
        let _ = poll(stack, 1_000 + 32_000);
        let ended: Vec<Said> = heard
            .of(call)
            .into_iter()
            .filter(|said| said.kind == SipralEventKind::CallEnded)
            .collect();
        assert_eq!(ended.len(), 1, "{protocol:?}: {:?}", heard.of(call));
        assert_eq!(
            ended[0].end_reason,
            SipralCallEndReason::Unreachable as u32,
            "{protocol:?}"
        );
        assert_eq!(
            ended[0].status_code, 0,
            "{protocol:?}: nothing answered, so no status is reported"
        );
        assert_eq!(written, 1, "{protocol:?}: a stream carries the INVITE once");
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }
}

// -- a name cut between two reads ------------------------------------------------

/// The caller's name, in characters of two, three and four bytes.
const NAME: &str = "Zo\u{eb} \u{65e5}\u{672c} \u{1f4de}";

/// An INVITE over TCP from a caller called [`NAME`].
fn named_invitation() -> Vec<u8> {
    let offer = b"v=0\r\no=- 1 1 IN IP4 203.0.113.5\r\ns=-\r\nc=IN IP4 203.0.113.5\r\n\
t=0 0\r\nm=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
    let mut out = format!(
        "INVITE sip:alice@192.0.2.10:5060;transport=tcp SIP/2.0\r\n\
Via: SIP/2.0/TCP 203.0.113.5:5060;branch=z9hG4bK-named-in\r\n\
Max-Forwards: 70\r\n\
From: \"{NAME}\" <sip:bob@example.com>;tag=farend\r\n\
To: <sip:alice@example.com>\r\n\
Call-ID: named-in@203.0.113.5\r\n\
CSeq: 1 INVITE\r\n\
Contact: <sip:bob@203.0.113.5:5060;transport=tcp>\r\n\
Content-Type: application/sdp\r\n\
Content-Length: {}\r\n\r\n",
        offer.len()
    )
    .into_bytes();
    out.extend_from_slice(offer);
    out
}

/// A display name in UTF-8, arriving over TCP in two reads that cut it
/// inside a character — every place inside every character of it. A stack
/// that decoded each read as it came would hand the application two broken
/// halves, or replacement characters; this one frames the message first
/// (RFC 3261 §18.3) and the name comes out whole, byte for byte.
#[test]
fn a_display_name_cut_between_two_reads_arrives_whole() {
    let invite = named_invitation();
    let start = invite
        .windows(NAME.len())
        .position(|window| window == NAME.as_bytes())
        .expect("the name is in the INVITE");
    let inside: Vec<usize> = (1..NAME.len())
        .filter(|at| !NAME.is_char_boundary(*at))
        .map(|at| start + at)
        .collect();
    assert_eq!(
        inside.len(),
        1 + 2 * 2 + 3,
        "every byte after a character's first"
    );
    for cut in inside {
        let mut observed = Observed::default();
        let mut settings = config(record, &mut observed);
        settings.transport = SipralTransport::Tcp as u32;
        let (status, stack) = create(&settings);
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let _account = account_on(stack);
        let local = crate::stack::tests::BIND;
        let remote = "203.0.113.5:5060";
        let status = unsafe {
            crate::transport::sipral_stack_transport_bind(
                stack,
                SIPRAL_TRANSPORT_MAIN,
                0,
                local.as_ptr().cast::<c_char>(),
                local.len(),
                remote.as_ptr().cast::<c_char>(),
                remote.len(),
                900,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        for (piece, now) in [(&invite[..cut], 1_000), (&invite[cut..], 1_001)] {
            let status = unsafe {
                crate::transport::sipral_stack_receive_stream(
                    stack,
                    SIPRAL_TRANSPORT_MAIN,
                    piece.as_ptr(),
                    piece.len(),
                    now,
                )
            };
            assert_eq!(
                status,
                SipralStatus::Ok,
                "cut at {cut}: {}",
                last_error_text()
            );
            let _ = poll(stack, now);
        }
        let incoming: Vec<Vec<u8>> = observed
            .calls
            .iter()
            .filter(|seen| seen.kind == SipralEventKind::IncomingCall)
            .map(|seen| seen.from_display.clone())
            .collect();
        assert_eq!(
            incoming,
            vec![NAME.as_bytes().to_vec()],
            "cut at {cut}, {} bytes into the name",
            cut - start
        );
        assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
    }
}

// -- the millisecond an event is raised at -------------------------------------

/// Time is the application's `now_ms`, and nothing between it and an event
/// rounds it: a retransmission due 500 ms after the INVITE goes at a poll at
/// exactly 500 ms and not at 499, `next_poll_in_ms` names the millisecond,
/// and the end at Timer B is raised by the poll at 32 000 ms and not by the
/// one at 31 999.
#[test]
fn an_event_is_raised_at_the_millisecond_its_deadline_names() {
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, SipralTransport::Udp);
    let account = account_on(stack);
    let placed_at = 1_234;
    let (status, call) = place(stack, account, &call_config(), placed_at);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(sent(stack).len(), 1);

    let mut result = poll_result();
    assert_eq!(
        unsafe { sipral_stack_poll(stack, placed_at, &raw mut result) },
        SipralStatus::Ok
    );
    assert_eq!(result.has_deadline, 1);
    assert_eq!(result.next_poll_in_ms, 500, "Timer A, to the millisecond");
    let _ = poll(stack, placed_at + 499);
    assert!(sent(stack).is_empty(), "a millisecond early");
    let _ = poll(stack, placed_at + 500);
    assert_eq!(sent(stack).len(), 1, "due at 500 ms, sent at 500 ms");

    let target = placed_at + 31_999;
    let mut now = placed_at + 500;
    while now < target {
        let mut result = poll_result();
        assert_eq!(
            unsafe { sipral_stack_poll(stack, now, &raw mut result) },
            SipralStatus::Ok
        );
        let _ = sent(stack);
        let step = if result.has_deadline == 1 {
            result.next_poll_in_ms.max(1)
        } else {
            1_000
        };
        now = (now + step).min(target);
    }
    let _ = poll(stack, placed_at + 31_999);
    assert!(
        heard
            .of(call)
            .iter()
            .all(|said| said.kind != SipralEventKind::CallEnded),
        "ended a millisecond early"
    );
    let _ = poll(stack, placed_at + 32_000);
    assert!(
        heard
            .of(call)
            .iter()
            .any(|said| said.kind == SipralEventKind::CallEnded),
        "Timer B is 32 000 ms, and the poll at that millisecond raises it"
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

// -- a CANCEL before anything came back ----------------------------------------

/// RFC 3261 §9.1: "If no provisional response has been received, the CANCEL
/// request MUST NOT be sent; rather, the client MUST wait for the arrival of
/// a provisional response before sending the request." A hang-up before
/// anything came back is held — nothing is written — and goes the moment a
/// 100 arrives; the 487 then ends the call as cancelled.
#[test]
fn a_hangup_before_any_provisional_holds_the_cancel_until_one_arrives() {
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, SipralTransport::Udp);
    let account = account_on(stack);
    let (status, call) = place(stack, account, &call_config(), 1_000);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let invite = sent(stack).pop().expect("the INVITE");

    assert_eq!(
        unsafe { sipral_call_hangup(stack, call, 1_010) },
        SipralStatus::Ok,
        "{}",
        last_error_text()
    );
    let _ = poll(stack, 1_010);
    assert!(
        sent(stack)
            .iter()
            .all(|message| !message.starts_with(b"CANCEL ")),
        "a CANCEL went before anything came back"
    );

    deliver(stack, &answered_with(&invite, 100, "Trying"), 1_050);
    let _ = poll(stack, 1_050);
    let out = sent(stack);
    assert!(
        out.iter().any(|message| message.starts_with(b"CANCEL ")),
        "the 100 arrived and the CANCEL did not go: {:?}",
        out.iter()
            .map(|message| start_line(message))
            .collect::<Vec<_>>()
    );

    let mut terminated = answered_with(&invite, 487, "Request Terminated");
    terminated = String::from_utf8_lossy(&terminated)
        .replacen(
            "To: <sip:bob@example.com>",
            "To: <sip:bob@example.com>;tag=farend",
            1,
        )
        .into_bytes();
    deliver(stack, &terminated, 1_100);
    let _ = poll(stack, 1_100);
    let ended: Vec<Said> = heard
        .of(call)
        .into_iter()
        .filter(|said| said.kind == SipralEventKind::CallEnded)
        .collect();
    assert_eq!(ended.len(), 1, "{:?}", heard.of(call));
    assert_eq!(ended[0].end_reason, SipralCallEndReason::Cancelled as u32);
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// The same hang-up, and nothing ever comes back: no CANCEL is ever sent —
/// there is nothing to send one after — and the call still ends, at Timer B.
#[test]
fn a_hangup_before_any_provisional_to_a_silent_peer_sends_no_cancel_and_still_ends() {
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, SipralTransport::Udp);
    let account = account_on(stack);
    let (status, call) = place(stack, account, &call_config(), 1_000);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let _ = sent(stack);
    assert_eq!(
        unsafe { sipral_call_hangup(stack, call, 1_010) },
        SipralStatus::Ok
    );
    let mut now = 1_010;
    while now <= 1_000 + 32_100 {
        let _ = poll(stack, now.min(1_000 + 32_000));
        assert!(
            sent(stack)
                .iter()
                .all(|message| !message.starts_with(b"CANCEL ")),
            "a CANCEL went at {now} ms with nothing come back"
        );
        now += 100;
    }
    assert!(
        heard
            .of(call)
            .iter()
            .any(|said| said.kind == SipralEventKind::CallEnded),
        "{:?}",
        heard.of(call)
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

/// The same hang-up, and the first thing back is a 180: the CANCEL goes on
/// it, since any provisional response will do.
#[test]
fn a_hangup_held_for_a_provisional_goes_on_a_ringing_as_on_a_trying() {
    let mut heard = Heard::default();
    let stack = stack_hearing(&mut heard, SipralTransport::Udp);
    let account = account_on(stack);
    let (status, call) = place(stack, account, &call_config(), 1_000);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let invite = sent(stack).pop().expect("the INVITE");
    assert_eq!(
        unsafe { sipral_call_hangup(stack, call, 1_010) },
        SipralStatus::Ok
    );
    let _ = poll(stack, 1_010);
    assert!(
        sent(stack)
            .iter()
            .all(|message| !message.starts_with(b"CANCEL "))
    );
    deliver(stack, &ringing(&invite), 1_020);
    let _ = poll(stack, 1_020);
    assert!(
        sent(stack)
            .iter()
            .any(|message| message.starts_with(b"CANCEL ")),
        "the 180 arrived and the CANCEL did not go"
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}
