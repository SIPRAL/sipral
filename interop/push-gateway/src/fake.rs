// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The lab's notification service: what APNs and FCM are to a phone, in a
//! few datagrams.
//!
//! A device subscribes and gets a token, the way a phone's operating system
//! hands an application its device token (RFC 8599 §3, Figure 1's
//! "Subscribe" and "PRID"); the proxy sends it a push by that token, and the
//! push is delivered to the address the subscription came from. A device can
//! subscribe asking for its pushes to be lost after they are accepted, which
//! is what a phone out of coverage looks like from the proxy's side. Every
//! line it prints is a record of what it was asked and what it did.
//!
//! The words on the wire, one datagram each:
//!
//! ```text
//! device -> service   SUBSCRIBE deliver | SUBSCRIBE lose
//! service -> device   TOKEN <hex>
//! proxy -> service    PUSH <token> <id>\n<payload>
//! service -> proxy    ACCEPTED <n> | REJECTED <why>
//! service -> device   WAKE\n<payload>
//! ```

use std::collections::HashMap;
use std::fmt::Write as _;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use ring::rand::{SecureRandom as _, SystemRandom};

use crate::push::{PushOutcome, PushRequest};

/// Run the service on `listen` until the process is stopped.
pub(crate) fn serve(listen: SocketAddr) -> Result<(), String> {
    let socket = UdpSocket::bind(listen).map_err(|error| format!("binding {listen}: {error}"))?;
    println!("  pns   the lab's notification service on {listen}");
    let random = SystemRandom::new();
    let mut devices: HashMap<String, (SocketAddr, bool)> = HashMap::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let Ok((length, from)) = socket.recv_from(&mut buffer) else {
            continue;
        };
        let text = String::from_utf8_lossy(buffer.get(..length).unwrap_or_default()).into_owned();
        let (line, payload) = text.split_once('\n').unwrap_or((text.as_str(), ""));
        let words: Vec<&str> = line.split_whitespace().collect();
        let answer = match words.as_slice() {
            ["SUBSCRIBE", mode @ ("deliver" | "lose")] => {
                let mut bytes = [0u8; 16];
                if random.fill(&mut bytes).is_err() {
                    continue;
                }
                let mut token = String::new();
                for byte in bytes {
                    let _ = write!(token, "{byte:02x}");
                }
                let lose = *mode == "lose";
                println!(
                    "  pns   {from} subscribed: token {}…, pushes {}",
                    token.get(..8).unwrap_or_default(),
                    if lose { "lost" } else { "delivered" }
                );
                devices.insert(token.clone(), (from, lose));
                format!("TOKEN {token}")
            }
            ["PUSH", token, id] => match devices.get(*token) {
                None => {
                    println!("  pns   push {id} for a token nobody holds: rejected");
                    "REJECTED unknown token".to_owned()
                }
                Some((device, lose)) => {
                    count += 1;
                    if *lose {
                        println!("  pns   push {id} accepted and lost on its way: {payload}");
                    } else {
                        let _ = socket.send_to(format!("WAKE\n{payload}").as_bytes(), device);
                        println!("  pns   push {id} delivered to {device}: {payload}");
                    }
                    format!("ACCEPTED {count}")
                }
            },
            _ => continue,
        };
        let _ = socket.send_to(answer.as_bytes(), from);
    }
}

/// The proxy's side: one push asked of the service at `service`.
pub(crate) fn send(service: SocketAddr, push: &PushRequest) -> PushOutcome {
    let socket = match UdpSocket::bind(if service.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }) {
        Ok(socket) => socket,
        Err(error) => return PushOutcome::Failed(format!("a socket: {error}")),
    };
    let _ = socket.set_read_timeout(Some(Duration::from_secs(3)));
    let request = format!("PUSH {} {}\n{}", push.prid, push.id, push.payload());
    if let Err(error) = socket.send_to(request.as_bytes(), service) {
        return PushOutcome::Failed(format!("sending to the lab's service: {error}"));
    }
    let mut buffer = [0u8; 512];
    match socket.recv_from(&mut buffer) {
        Ok((length, _)) => {
            let answer =
                String::from_utf8_lossy(buffer.get(..length).unwrap_or_default()).into_owned();
            match answer.strip_prefix("ACCEPTED ") {
                Some(number) => PushOutcome::Accepted(format!("the lab's service, push {number}")),
                None => PushOutcome::Failed(format!("the lab's service: {answer}")),
            }
        }
        Err(error) => PushOutcome::Failed(format!("the lab's service did not answer: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::push::PushKind;

    #[test]
    fn a_subscribed_device_is_woken_and_a_stranger_is_refused() {
        let probe = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        let address = probe.local_addr().expect("address");
        drop(probe);
        std::thread::spawn(move || serve(address));
        let device = UdpSocket::bind("127.0.0.1:0").expect("a socket");
        device
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("timeout");
        let mut token = String::new();
        let mut buffer = [0u8; 1024];
        for _ in 0..50 {
            device.send_to(b"SUBSCRIBE deliver", address).expect("sent");
            if let Ok((length, _)) = device.recv_from(&mut buffer) {
                token = String::from_utf8_lossy(&buffer[..length])
                    .trim_start_matches("TOKEN ")
                    .to_owned();
                break;
            }
        }
        assert_eq!(token.len(), 32);
        let push = PushRequest {
            id: 3,
            provider: "apns".into(),
            prid: token,
            param: None,
            kind: PushKind::Call,
            caller: Some("sip:bob@example.com".into()),
            name: None,
            call_id: None,
        };
        assert!(matches!(send(address, &push), PushOutcome::Accepted(_)));
        // A SUBSCRIBE resent while the first one's answer was on its way is
        // answered too: that second TOKEN can come before the WAKE.
        device
            .set_read_timeout(Some(Duration::from_secs(10)))
            .expect("timeout");
        let woken = loop {
            let (length, _) = device.recv_from(&mut buffer).expect("woken");
            if !buffer[..length].starts_with(b"TOKEN ") {
                break buffer[..length].to_vec();
            }
        };
        assert_eq!(
            woken,
            b"WAKE\n{\"kind\":\"call\",\"caller\":\"sip:bob@example.com\"}"
        );
        let stranger = PushRequest {
            prid: "00".into(),
            ..push
        };
        assert_eq!(
            send(address, &stranger),
            PushOutcome::Failed("the lab's service: REJECTED unknown token".into())
        );
    }
}
