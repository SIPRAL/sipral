// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! Two accounts on two servers in one stack, sharing its one media engine:
//! each server's call reaches its own account, by the server it came from
//! where the two accounts' contacts are the same, and both calls are carried
//! side by side.

use std::net::SocketAddr;
use std::time::Instant;

use sipral_ua::{Account, AccountId, CallHandle};

use crate::codec::CodecCatalog;
use crate::event::Event;
use crate::tests::{
    Stack, callee_media, callee_sip, caller_media, caller_sip, carol_media, carol_sip, uri,
};
use crate::{OutgoingCall, TransportId, UaEvent};

const UDP: TransportId = TransportId(1);

fn pcmu() -> CodecCatalog {
    CodecCatalog::with_order(&["PCMU"]).expect("an order")
}

/// This end's line `100` on `server`, reachable at the same contact as every
/// other line it holds.
fn line(me: &mut Stack, domain: &str, server: SocketAddr) -> AccountId {
    me.agent.add_account(Account::new(
        uri(&format!("sip:100@{domain}")),
        uri(&format!("sip:{domain}")),
        uri("sip:100@192.0.2.1"),
        UDP,
        server,
    ))
}

/// `server` calls `100` at this end's contact, and this end hears it.
fn call_in(
    me: &mut Stack,
    server: &mut Stack,
    from: SocketAddr,
    media: SocketAddr,
    now: Instant,
) -> (AccountId, CallHandle) {
    let account = server.account("pbx", caller_sip());
    server
        .engine
        .place(
            &mut server.agent,
            account,
            OutgoingCall::new(uri("sip:100@192.0.2.1")).to_address(UDP, caller_sip()),
            media,
            now,
        )
        .expect("the INVITE goes");
    server.drain(now, false);
    me.heard.clear();
    for datagram in server.outbound() {
        me.deliver(&datagram, from, now);
    }
    me.drain(now, false);
    me.heard
        .iter()
        .find_map(|event| match event {
            Event::Signalling(UaEvent::IncomingCall {
                call,
                account: Some(account),
                ..
            }) => Some((*account, *call)),
            _ => None,
        })
        .expect("a call for a line")
}

#[test]
fn two_servers_reach_their_own_lines_and_one_engine_carries_both_calls() {
    let now = Instant::now();
    let mut me = Stack::new(11, caller_sip(), caller_media(), pcmu(), now);
    let mut first = Stack::new(22, callee_sip(), callee_media(), pcmu(), now);
    let mut second = Stack::new(33, carol_sip(), carol_media(), pcmu(), now);
    let on_first = line(&mut me, "first.example.com", callee_sip());
    let on_second = line(&mut me, "second.example.com", carol_sip());

    let (account, from_second) = call_in(&mut me, &mut second, carol_sip(), carol_media(), now);
    assert_eq!(
        account, on_second,
        "the contact names both; the server says which"
    );
    let (account, from_first) = call_in(&mut me, &mut first, callee_sip(), callee_media(), now);
    assert_eq!(account, on_first);

    let near: SocketAddr = "192.0.2.1:40010".parse().expect("an address");
    me.engine
        .answer(&mut me.agent, from_first, caller_media(), now)
        .expect("the first answered");
    me.engine
        .answer(&mut me.agent, from_second, near, now)
        .expect("the second answered");
    // each 200 to the server it answers, and each ACK back
    me.drain(now, false);
    while let Some(transmit) = me.agent.poll_transmit() {
        let server = if transmit.destination == callee_sip() {
            &mut first
        } else {
            &mut second
        };
        server.deliver(&transmit.payload, caller_sip(), now);
    }
    for (server, from) in [(&mut first, callee_sip()), (&mut second, carol_sip())] {
        server.drain(now, false);
        for datagram in server.outbound() {
            me.deliver(&datagram, from, now);
        }
    }
    me.drain(now, false);
    let carried: Vec<CallHandle> = me.engine.active().collect();
    assert!(
        carried.contains(&from_first) && carried.contains(&from_second),
        "{carried:?}"
    );
}
