// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A REFER from outside any call, sent at a stack driven through the C ABI.
//!
//! `scripts/lab.sh`'s referral step runs `harness-c listen` on the lab
//! network and points this at it: a switchboard asking that stack's line to
//! ring an extension on Asterisk — RFC 3515 §4.1's own flow, with the stack
//! under test as Agent B. This end is written by hand on a plain UDP socket
//! rather than on a Sipral stack of its own, so that the only Sipral code in
//! the exchange is the code being proved.
//!
//! Two verdicts. With the listener's referrals off, the REFER is answered
//! 403 and nothing else follows. With them on, it is answered 202; a NOTIFY
//! of the `refer` package follows at once with §2.4.5's `SIP/2.0 100 Trying`
//! in a `message/sipfrag` and an `active` subscription that says how long it
//! runs; and the last NOTIFY carries the placed call's own 200 and ends the
//! subscription with `terminated;reason=noresource` (§2.4.7). Every NOTIFY
//! is answered 200, as a referrer must.

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sipral_core::msg::{HeaderName, ParseMode, ParseScratch, RawMessage, parse};

use crate::route_to;

/// How long the whole exchange may take: the 202, then a call placed through
/// Asterisk to its echo, rung, answered and dwelt on before the listener
/// hangs up.
const PATIENCE: Duration = Duration::from_secs(30);

/// How long a refusal is waited for, and how long after it nothing more may
/// arrive.
const REFUSAL: Duration = Duration::from_secs(5);

/// What one run has to see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Expect {
    /// Refused 403, and nothing after it.
    Refused,
    /// Taken: 202, then NOTIFYs from 100 to the placed call's 200.
    Taken,
}

/// One message that arrived, as text.
struct Arrived {
    text: String,
}

/// Send the REFER at `remote`, asking its line `user` to call `refer_to`,
/// and judge what comes back.
///
/// # Errors
/// The first thing that did not hold, named.
pub(crate) fn run(
    remote: SocketAddr,
    user: &str,
    domain: &str,
    refer_to: &str,
    expect: Expect,
) -> Result<String, String> {
    let socket = UdpSocket::bind(SocketAddr::new(route_to(remote), 0))
        .map_err(|error| format!("cannot bind the referrer's socket: {error}"))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .map_err(|error| format!("cannot set a read timeout: {error}"))?;
    let local = socket
        .local_addr()
        .map_err(|error| format!("the referrer's socket has no address: {error}"))?;
    // a Call-ID, tag and branch of this run's own, so a retransmission of
    // an earlier run's REFER is never taken for this one's
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let unique = format!("{}-{clock}-{}", std::process::id(), local.port());
    let refer = format!(
        "REFER sip:{user}@{remote} SIP/2.0\r\n\
Via: SIP/2.0/UDP {local};branch=z9hG4bK-click-{unique}\r\n\
Max-Forwards: 70\r\n\
From: <sip:switchboard@{domain}>;tag=switchboard-{unique}\r\n\
To: <sip:{user}@{domain}>\r\n\
Call-ID: click-to-dial-{unique}@{local}\r\n\
CSeq: 1 REFER\r\n\
Contact: <sip:switchboard@{local}>\r\n\
Refer-To: <{refer_to}>\r\n\
Referred-By: <sip:switchboard@{domain}>\r\n\
Content-Length: 0\r\n\
\r\n"
    );
    let started = Instant::now();
    socket
        .send_to(refer.as_bytes(), remote)
        .map_err(|error| format!("cannot send the REFER: {error}"))?;

    match expect {
        Expect::Refused => refused(&socket, started),
        Expect::Taken => taken(&socket, started),
    }
}

/// The 403, and silence after it.
fn refused(socket: &UdpSocket, started: Instant) -> Result<String, String> {
    let seen = read(socket, started + REFUSAL, |seen| {
        seen.iter().any(|one| one.text.starts_with("SIP/2.0 4"))
    });
    let answer = seen
        .iter()
        .find(|one| one.text.starts_with("SIP/2.0 "))
        .ok_or("nothing answered the REFER")?;
    if !answer.text.starts_with("SIP/2.0 403 ") {
        return Err(format!("answered {}", first_line(&answer.text)));
    }
    let after = read(socket, Instant::now() + Duration::from_secs(2), |_| false);
    if let Some(more) = after
        .iter()
        .chain(seen.iter())
        .find(|one| one.text.starts_with("NOTIFY ") || one.text.starts_with("SIP/2.0 202 "))
    {
        return Err(format!(
            "a refused REFER went on: {}",
            first_line(&more.text)
        ));
    }
    Ok(format!(
        " — refused 403 in {} ms, nothing after it",
        started.elapsed().as_millis()
    ))
}

/// The 202, the 100, and the call's own 200 ending the subscription.
fn taken(socket: &UdpSocket, started: Instant) -> Result<String, String> {
    let seen = read(socket, started + PATIENCE, |seen| {
        seen.iter()
            .filter(|one| one.text.starts_with("NOTIFY "))
            .any(|one| state_of(&one.text).is_some_and(|state| state.starts_with("terminated")))
    });
    let accepted = seen
        .iter()
        .find(|one| one.text.starts_with("SIP/2.0 "))
        .ok_or("nothing answered the REFER")?;
    if !accepted.text.starts_with("SIP/2.0 202 ") {
        return Err(format!("answered {}", first_line(&accepted.text)));
    }
    let notifies: Vec<&Arrived> = seen
        .iter()
        .filter(|one| one.text.starts_with("NOTIFY "))
        .collect();
    let first = notifies
        .first()
        .ok_or("the 202 opened no subscription: no NOTIFY")?;
    judge_notify(&first.text)?;
    if !body_of(&first.text).starts_with("SIP/2.0 100 ") {
        return Err(format!("the first NOTIFY said {:?}", body_of(&first.text)));
    }
    if !state_of(&first.text).is_some_and(|state| state.starts_with("active;expires=")) {
        return Err(format!(
            "the first NOTIFY's Subscription-State is {:?}",
            state_of(&first.text)
        ));
    }
    let last = notifies.last().ok_or("no NOTIFY")?;
    judge_notify(&last.text)?;
    if state_of(&last.text).as_deref() != Some("terminated;reason=noresource") {
        return Err(format!(
            "the subscription never ended with the call's answer: {:?}",
            notifies
                .iter()
                .map(|one| state_of(&one.text))
                .collect::<Vec<_>>()
        ));
    }
    if !body_of(&last.text).starts_with("SIP/2.0 200 ") {
        return Err(format!("the placed call ended {:?}", body_of(&last.text)));
    }
    Ok(format!(
        " — 202, then {} NOTIFYs from 100 to 200 in {} ms",
        notifies.len(),
        started.elapsed().as_millis()
    ))
}

/// What every NOTIFY about a REFER has to carry (§2.4.4, §2.4.5).
fn judge_notify(text: &str) -> Result<(), String> {
    let event = header(text, HeaderName::Event).unwrap_or_default();
    if !event.starts_with("refer") {
        return Err(format!("a NOTIFY for the {event:?} package"));
    }
    let kind = header(text, HeaderName::ContentType).unwrap_or_default();
    if !kind.starts_with("message/sipfrag") {
        return Err(format!("a NOTIFY carrying {kind:?}"));
    }
    Ok(())
}

/// Everything that arrives until `deadline`, or until `done` says it has what
/// it came for, each NOTIFY answered 200 on the way.
fn read(socket: &UdpSocket, deadline: Instant, done: impl Fn(&[Arrived]) -> bool) -> Vec<Arrived> {
    let mut seen: Vec<Arrived> = Vec::new();
    let mut buffer = vec![0_u8; 65_536];
    while Instant::now() < deadline && !done(&seen) {
        let Ok((length, from)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let text = String::from_utf8_lossy(buffer.get(..length).unwrap_or_default()).into_owned();
        if text.starts_with("NOTIFY ") {
            let ok = ok_to(&text);
            let _ = socket.send_to(ok.as_bytes(), from);
        }
        seen.push(Arrived { text });
    }
    seen
}

/// The 200 a referrer owes every NOTIFY it is sent.
fn ok_to(request: &str) -> String {
    let mut out = String::from("SIP/2.0 200 OK\r\n");
    for name in [
        HeaderName::Via,
        HeaderName::From,
        HeaderName::To,
        HeaderName::CallId,
        HeaderName::CSeq,
    ] {
        if let Some(value) = header(request, name) {
            out.push_str(name.canonical());
            out.push_str(": ");
            out.push_str(&value);
            out.push_str("\r\n");
        }
    }
    out.push_str("Content-Length: 0\r\n\r\n");
    out
}

fn with<T>(text: &str, read: impl FnOnce(&RawMessage<'_>) -> T) -> Option<T> {
    let mut scratch = ParseScratch::new();
    parse(text.as_bytes(), &mut scratch, ParseMode::Lenient)
        .ok()
        .map(|message| read(&message))
}

fn header(text: &str, name: HeaderName<'_>) -> Option<String> {
    with(text, |message| {
        message
            .header(name)
            .map(|value| String::from_utf8_lossy(value).into_owned())
    })
    .flatten()
}

fn state_of(text: &str) -> Option<String> {
    header(text, HeaderName::SubscriptionState)
}

fn body_of(text: &str) -> String {
    with(text, |message| {
        String::from_utf8_lossy(message.body()).into_owned()
    })
    .unwrap_or_default()
}

fn first_line(text: &str) -> &str {
    text.lines().next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{body_of, ok_to, state_of};

    const NOTIFY: &str = "NOTIFY sip:switchboard@192.0.2.9:5060 SIP/2.0\r\n\
Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bKn1\r\n\
Max-Forwards: 70\r\n\
From: <sip:labuser@asterisk>;tag=b\r\n\
To: <sip:switchboard@asterisk>;tag=a\r\n\
Call-ID: click@192.0.2.9\r\n\
CSeq: 1 NOTIFY\r\n\
Event: refer;id=1\r\n\
Subscription-State: active;expires=3600\r\n\
Content-Type: message/sipfrag;version=2.0\r\n\
Content-Length: 20\r\n\
\r\n\
SIP/2.0 100 Trying\r\n";

    #[test]
    fn a_notify_is_read_for_its_state_and_its_sipfrag_and_answered_in_its_own_dialog() {
        assert_eq!(state_of(NOTIFY).as_deref(), Some("active;expires=3600"));
        assert!(body_of(NOTIFY).starts_with("SIP/2.0 100 "));
        let ok = ok_to(NOTIFY);
        assert!(ok.starts_with("SIP/2.0 200 OK\r\n"));
        assert!(ok.contains("CSeq: 1 NOTIFY\r\n"));
        assert!(ok.contains("To: <sip:switchboard@asterisk>;tag=a\r\n"));
    }
}
