// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The networking component end to end through the C ABI, against servers on loopback: a name
//! server that knows the SIP domain only by its SRV record, a SIP server over TLS with a
//! throwaway authority that registers, answers, holds and hangs up, and a far end for the RTP.
//! The test opens no socket of its own toward the stack: the component does all of it.

use std::collections::HashMap;
use std::ffi::c_char;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SRV};
use hickory_proto::rr::{Name, RData, Record as DnsRecord, RecordType as DnsType};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::{
    SipralNetworkConfig, sipral_network_locate, sipral_network_media_attach,
    sipral_network_media_capture, sipral_network_media_open, sipral_network_run,
    sipral_network_start, sipral_network_stop,
};
use crate::account::tests::account_config;
use crate::account::{
    sipral_account_add, sipral_account_register, sipral_account_registration_state,
};
use crate::call::tests::call_config;
use crate::call::{sipral_call_hangup, sipral_call_hold, sipral_call_place, sipral_call_resume};
use crate::error::last_error_text;
use crate::event::{SipralEventKind, SipralRegistrationState};
use crate::handle::{SIPRAL_HANDLE_NONE, SipralHandle};
use crate::media::{
    SIPRAL_ADDRESS_BYTES, SipralMediaInfo, SipralPlayback, sipral_call_media, sipral_media_info,
    sipral_media_playback,
};
use crate::stack::tests::{Observed, config, create, record};
use crate::stack::{SipralTransport, sipral_stack_destroy};
use crate::status::SipralStatus;

/// The SIP domain, which has no address of its own: only an SRV record.
const DOMAIN: &str = "example.test";

/// A throwaway authority, and the server certificate it signs for the domain.
struct Pki {
    pem: String,
    chain: Vec<CertificateDer<'static>>,
    key: KeyPair,
}

fn pki() -> Pki {
    let authority_key = KeyPair::generate().unwrap();
    let mut authority = CertificateParams::new(Vec::<String>::new()).unwrap();
    authority.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    authority
        .distinguished_name
        .push(DnType::CommonName, "Sipral test authority");
    authority.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let pem = authority.self_signed(&authority_key).unwrap().pem();
    let key = KeyPair::generate().unwrap();
    let leaf = CertificateParams::new(vec![DOMAIN.to_owned()])
        .unwrap()
        .signed_by(&key, &Issuer::from_params(&authority, &authority_key))
        .unwrap();
    Pki {
        pem,
        chain: vec![leaf.der().clone()],
        key,
    }
}

/// One SIP message off a stream: its head, its body, and how many bytes it took. Keep-alive
/// line breaks before it are taken too.
fn framed(buffer: &[u8]) -> Option<(String, String, usize)> {
    let skipped = buffer
        .iter()
        .take_while(|byte| **byte == b'\r' || **byte == b'\n')
        .count();
    let rest = &buffer[skipped..];
    let end = rest.windows(4).position(|window| window == b"\r\n\r\n")?;
    let head = String::from_utf8_lossy(&rest[..end]).into_owned();
    let length = head
        .split("\r\n")
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            let name = name.trim().to_ascii_lowercase();
            (name == "content-length" || name == "l").then(|| value.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    let total = end + 4 + length;
    if rest.len() < total {
        return None;
    }
    let body = String::from_utf8_lossy(&rest[end + 4..total]).into_owned();
    Some((head, body, skipped + total))
}

/// The header lines of `head` with one of `names`, compact forms included.
fn lines<'a>(head: &'a str, names: &[&str]) -> Vec<&'a str> {
    head.split("\r\n")
        .skip(1)
        .filter(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| names.contains(&name.trim().to_ascii_lowercase().as_str()))
        })
        .collect()
}

/// Where an offer's audio goes: its `c=` address at its `m=audio` port.
fn offered(body: &str) -> Option<SocketAddr> {
    let address = body
        .lines()
        .find_map(|line| line.strip_prefix("c=IN IP4 "))?
        .trim();
    let port = body
        .lines()
        .find_map(|line| line.strip_prefix("m=audio "))?
        .split(' ')
        .next()?;
    format!("{address}:{port}").parse().ok()
}

/// The answer of a SIP server to one request, or nothing for an ACK.
fn answer(
    head: &str,
    body: &str,
    own: SocketAddr,
    rtp: SocketAddr,
    version: usize,
) -> Option<String> {
    let method = head.split(' ').next()?;
    if method == "ACK" || head.starts_with("SIP/2.0") {
        return None;
    }
    let mut response = String::from("SIP/2.0 200 OK\r\n");
    for line in lines(head, &["via", "v", "from", "f", "call-id", "i", "cseq"]) {
        response.push_str(line);
        response.push_str("\r\n");
    }
    for line in lines(head, &["to", "t"]) {
        response.push_str(line);
        if !line.contains(";tag=") {
            response.push_str(";tag=uas");
        }
        response.push_str("\r\n");
    }
    let mut sdp = String::new();
    match method {
        "REGISTER" => {
            for line in lines(head, &["contact", "m"]) {
                response.push_str(line);
                response.push_str(";expires=300\r\n");
            }
            response.push_str("Expires: 300\r\n");
        }
        "INVITE" => {
            let _ = write!(response, "Contact: <sip:echo@{own};transport=tls>\r\n");
            response.push_str("Content-Type: application/sdp\r\n");
            let direction = if body.contains("a=sendonly") {
                "recvonly"
            } else {
                "sendrecv"
            };
            sdp = format!(
                "v=0\r\no=- 1 {version} IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
                 m=audio {} RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na={direction}\r\n",
                rtp.port()
            );
        }
        _ => {}
    }
    let _ = write!(response, "Content-Length: {}\r\n\r\n{sdp}", sdp.len());
    Some(response)
}

/// What the SIP server was sent: each request's method and body.
type Heard = Arc<Mutex<Vec<(String, String)>>>;

/// A SIP server over TLS on loopback, answering 200 to everything but an ACK, and telling the
/// far end where each offer wants its audio.
fn sip_server(pki: Pki, rtp: SocketAddr, offers: Sender<SocketAddr>) -> (SocketAddr, Heard) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = Arc::new(
        ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                pki.chain,
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pki.key.serialize_der())),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let own = listener.local_addr().unwrap();
    let heard: Heard = Arc::default();
    let noted = Arc::clone(&heard);
    thread::spawn(move || {
        for tcp in listener.incoming() {
            let Ok(tcp) = tcp else { continue };
            let mut stream =
                StreamOwned::new(ServerConnection::new(Arc::clone(&config)).unwrap(), tcp);
            let mut buffer = Vec::new();
            let mut chunk = [0_u8; 8192];
            let mut invites = 0;
            while let Ok(read) = stream.read(&mut chunk) {
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                while let Some((head, body, taken)) = framed(&buffer) {
                    buffer.drain(..taken);
                    let method = head.split(' ').next().unwrap_or_default().to_owned();
                    if method == "INVITE" {
                        invites += 1;
                        if let Some(target) = offered(&body) {
                            let _ = offers.send(target);
                        }
                    }
                    noted.lock().unwrap().push((method, body.clone()));
                    if let Some(response) = answer(&head, &body, own, rtp, invites) {
                        if stream.write_all(response.as_bytes()).is_err() {
                            return;
                        }
                        let _ = stream.flush();
                    }
                }
            }
        }
    });
    (own, heard)
}

/// The far end of the call's audio: PCMU every 20 ms to wherever the last offer said, and a
/// count of what came back.
fn far_end() -> (SocketAddr, Sender<SocketAddr>, Arc<AtomicUsize>) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let (offers, wanted): (Sender<SocketAddr>, Receiver<SocketAddr>) = channel();
    let received = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&received);
    thread::spawn(move || {
        let mut target = None;
        let mut sequence: u16 = 0;
        let mut timestamp: u32 = 0;
        let mut buffer = [0_u8; 2048];
        loop {
            while let Ok(next) = wanted.try_recv() {
                target = Some(next);
            }
            if let Ok((read, _)) = socket.recv_from(&mut buffer)
                && read >= 12
                && buffer[0] >> 6 == 2
                && buffer[1].trailing_zeros() >= 7
            {
                counted.fetch_add(1, Ordering::SeqCst);
            }
            if let Some(target) = target {
                let mut packet = vec![0x80, 0x00];
                packet.extend_from_slice(&sequence.to_be_bytes());
                packet.extend_from_slice(&timestamp.to_be_bytes());
                packet.extend_from_slice(&0x5150_5150_u32.to_be_bytes());
                packet.extend(std::iter::repeat_n(0xFF_u8, 160));
                if socket.send_to(&packet, target).is_err() {
                    return;
                }
                sequence = sequence.wrapping_add(1);
                timestamp = timestamp.wrapping_add(160);
            }
        }
    });
    (address, offers, received)
}

/// A name server on loopback that knows the domain by its SRV record alone, pointing at the
/// SIP server's port on a host it knows by its A record.
fn name_server(sip: SocketAddr) -> SocketAddr {
    let mut table: HashMap<(String, DnsType), RData> = HashMap::new();
    table.insert(
        (format!("_sips._tcp.{DOMAIN}"), DnsType::SRV),
        RData::SRV(SRV::new(
            10,
            0,
            sip.port(),
            Name::from_ascii(format!("pbx.{DOMAIN}.")).unwrap(),
        )),
    );
    table.insert(
        (format!("pbx.{DOMAIN}"), DnsType::A),
        RData::A(A(Ipv4Addr::LOCALHOST)),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok((read, from)) = socket.recv_from(&mut buffer) {
            let Ok(request) = Message::from_vec(&buffer[..read]) else {
                continue;
            };
            let mut response =
                Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
            response.metadata.authoritative = true;
            response.metadata.recursion_desired = request.metadata.recursion_desired;
            for query in &request.queries {
                response.add_query(query.clone());
                let name = query.name().to_utf8().trim_end_matches('.').to_lowercase();
                match table.get(&(name.clone(), query.query_type())) {
                    Some(data) => {
                        response.add_answer(DnsRecord::from_rdata(
                            query.name().clone(),
                            300,
                            data.clone(),
                        ));
                    }
                    None if !table.keys().any(|(known, _)| *known == name) => {
                        response.metadata.response_code = ResponseCode::NXDomain;
                    }
                    None => {}
                }
            }
            let _ = socket.send_to(&response.to_vec().unwrap(), from);
        }
    });
    address
}

fn text(value: &str) -> (*const c_char, usize) {
    (value.as_ptr().cast(), value.len())
}

/// Milliseconds since `origin`, the test's monotonic clock.
fn now(origin: Instant) -> u64 {
    u64::try_from(origin.elapsed().as_millis()).unwrap()
}

/// Run the component until `done` says so, fifteen seconds at most.
fn run_until(stack: SipralHandle, origin: Instant, what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !done() {
        assert!(Instant::now() < deadline, "{what}: not in fifteen seconds");
        let status = unsafe { sipral_network_run(stack, now(origin), 20) };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    }
}

fn written(buffer: &[c_char], needed: usize) -> String {
    let bytes: Vec<u8> = buffer[..needed - 1]
        .iter()
        .flat_map(|byte| byte.to_ne_bytes())
        .collect();
    String::from_utf8(bytes).unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn a_stack_registers_over_tls_at_a_domain_found_by_srv_and_holds_a_call_with_no_socket_of_its_own()
{
    let pki = pki();
    let authority = pki.pem.clone();
    let (rtp, offers, received) = far_end();
    let (sip, heard) = sip_server(pki, rtp, offers);
    let servers = name_server(sip).to_string();
    let origin = Instant::now();

    let (authority_pem, authority_pem_len) = text(&authority);
    let (name_servers, name_servers_len) = text(&servers);
    let network = SipralNetworkConfig {
        size: size_of::<SipralNetworkConfig>(),
        trust: super::SipralNetworkTrust::OnlyAuthority as u32,
        reserved: 0,
        authority_pem,
        authority_pem_len,
        pin_sha256: ptr::null(),
        pin_sha256_len: 0,
        client_certificate_pem: ptr::null(),
        client_certificate_pem_len: 0,
        client_key_pem: ptr::null(),
        client_key_pem_len: 0,
        name_servers,
        name_servers_len,
        tls_server_name: ptr::null(),
        tls_server_name_len: 0,
        connect_timeout_ms: 0,
        reserved_end: 0,
    };

    // RFC 3263 before any stack: the domain is found by SRV alone
    let uri = format!("sips:{DOMAIN}");
    let mut found = [0 as c_char; 256];
    let mut needed = 0_usize;
    let status = unsafe {
        sipral_network_locate(
            &raw const network,
            uri.as_ptr().cast(),
            uri.len(),
            SipralTransport::Tls as u32,
            found.as_mut_ptr(),
            found.len(),
            &raw mut needed,
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(written(&found, needed), sip.to_string());

    let mut observed = Observed::default();
    let mut stack_config = config(record, &mut observed);
    let bind = "127.0.0.1:0";
    (stack_config.bind_address, stack_config.bind_address_len) = text(bind);
    let (status, stack) = create(&stack_config);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let status = unsafe { sipral_network_start(stack, &raw const network, now(origin)) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(
        unsafe { sipral_network_start(stack, &raw const network, now(origin)) },
        SipralStatus::WrongState,
        "once per stack"
    );

    let aor = format!("sip:alice@{DOMAIN}");
    let registrar = format!("sip:{DOMAIN}");
    let contact = "sip:alice@127.0.0.1;transport=tls";
    let mut line = account_config();
    (line.aor, line.aor_len) = text(&aor);
    (line.registrar, line.registrar_len) = text(&registrar);
    (line.contact, line.contact_len) = text(contact);
    (line.registrar_address, line.registrar_address_len) = (ptr::null(), 0);
    (line.server_uri, line.server_uri_len) = text(&uri);
    line.stream_protocol = SipralTransport::Tls as u32;
    line.srtp = 1;
    let mut account = SIPRAL_HANDLE_NONE;
    let status = unsafe { sipral_account_add(stack, &raw const line, &raw mut account) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let status = unsafe { sipral_account_register(stack, account, now(origin)) };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    run_until(stack, origin, "registered", || {
        let mut state = 0_u32;
        let read = unsafe { sipral_account_registration_state(stack, account, &raw mut state) };
        read == SipralStatus::Ok && state == SipralRegistrationState::Registered as u32
    });

    let mut media_address = [0 as c_char; SIPRAL_ADDRESS_BYTES];
    let status = unsafe {
        sipral_network_media_open(
            stack,
            media_address.as_mut_ptr(),
            media_address.len(),
            &raw mut needed,
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let media_at = written(&media_address, needed);
    let target = format!("sip:echo@{DOMAIN}");
    let mut placing = call_config();
    (placing.target, placing.target_len) = text(&target);
    (placing.sdp, placing.sdp_len) = (ptr::null(), 0);
    (placing.media_address, placing.media_address_len) = text(&media_at);
    let mut call = SIPRAL_HANDLE_NONE;
    let status = unsafe {
        sipral_call_place(
            stack,
            account,
            &raw const placing,
            &raw mut call,
            now(origin),
        )
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    run_until(stack, origin, "media started", || {
        !observed.of(SipralEventKind::MediaStarted).is_empty()
    });

    let mut media = SIPRAL_HANDLE_NONE;
    assert_eq!(
        unsafe { sipral_call_media(stack, call, &raw mut media) },
        SipralStatus::Ok,
        "{}",
        last_error_text()
    );
    let status = unsafe {
        sipral_network_media_attach(stack, media_at.as_ptr().cast(), media_at.len(), call, media)
    };
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    let mut info = SipralMediaInfo {
        size: size_of::<SipralMediaInfo>(),
        ..unsafe { std::mem::zeroed() }
    };
    assert_eq!(
        unsafe { sipral_media_info(media, &raw mut info) },
        SipralStatus::Ok
    );
    let silence = vec![0_i16; info.frame_samples];
    let mut earpiece = vec![0_i16; info.frame_samples];
    let mut from_the_far_end = 0;
    run_until(stack, origin, "audio both ways", || {
        let status = unsafe {
            sipral_network_media_capture(stack, media, now(origin), silence.as_ptr(), silence.len())
        };
        assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
        let mut written = 0_usize;
        let mut source = 0_u32;
        let status = unsafe {
            sipral_media_playback(
                media,
                earpiece.as_mut_ptr(),
                earpiece.len(),
                &raw mut written,
                &raw mut source,
            )
        };
        if status == SipralStatus::Ok && source == SipralPlayback::Packet as u32 {
            from_the_far_end += 1;
        }
        from_the_far_end >= 5 && received.load(Ordering::SeqCst) >= 5
    });

    let invites = |heard: &Heard| -> Vec<String> {
        heard
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _)| method == "INVITE")
            .map(|(_, body)| body.clone())
            .collect()
    };
    assert_eq!(
        unsafe { sipral_call_hold(stack, call, now(origin)) },
        SipralStatus::Ok
    );
    run_until(stack, origin, "held", || {
        invites(&heard).len() == 2 && observed.kinds().contains(&SipralEventKind::SessionChanged)
    });
    assert!(
        invites(&heard)[1].contains("a=sendonly"),
        "{:?}",
        invites(&heard)
    );
    let changed = observed
        .kinds()
        .iter()
        .filter(|kind| **kind == SipralEventKind::SessionChanged)
        .count();
    assert_eq!(
        unsafe { sipral_call_resume(stack, call, now(origin)) },
        SipralStatus::Ok
    );
    run_until(stack, origin, "resumed", || {
        invites(&heard).len() == 3
            && observed
                .kinds()
                .iter()
                .filter(|kind| **kind == SipralEventKind::SessionChanged)
                .count()
                > changed
    });
    assert!(
        !invites(&heard)[2].contains("a=sendonly"),
        "{:?}",
        invites(&heard)
    );

    assert_eq!(
        unsafe { sipral_call_hangup(stack, call, now(origin)) },
        SipralStatus::Ok
    );
    run_until(stack, origin, "hung up", || {
        observed.kinds().contains(&SipralEventKind::CallEnded)
            && heard
                .lock()
                .unwrap()
                .iter()
                .any(|(method, _)| method == "BYE")
    });
    let methods: Vec<String> = heard
        .lock()
        .unwrap()
        .iter()
        .map(|(method, _)| method.clone())
        .collect();
    assert_eq!(
        methods,
        [
            "REGISTER", "INVITE", "ACK", "INVITE", "ACK", "INVITE", "ACK", "BYE"
        ],
        "everything went over the one TLS connection the component opened"
    );

    assert_eq!(unsafe { sipral_network_stop(stack) }, SipralStatus::Ok);
    assert_eq!(
        unsafe { sipral_network_stop(stack) },
        SipralStatus::WrongState
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

#[test]
fn a_server_whose_certificate_is_not_trusted_is_reported_with_the_reason() {
    let pki = pki();
    let (rtp, offers, _) = far_end();
    let (sip, _) = sip_server(pki, rtp, offers);
    let servers = name_server(sip).to_string();
    let origin = Instant::now();
    // the platform's store has never heard of the test authority
    let (name_servers, name_servers_len) = text(&servers);
    let network = SipralNetworkConfig {
        size: size_of::<SipralNetworkConfig>(),
        trust: super::SipralNetworkTrust::Platform as u32,
        reserved: 0,
        authority_pem: ptr::null(),
        authority_pem_len: 0,
        pin_sha256: ptr::null(),
        pin_sha256_len: 0,
        client_certificate_pem: ptr::null(),
        client_certificate_pem_len: 0,
        client_key_pem: ptr::null(),
        client_key_pem_len: 0,
        name_servers,
        name_servers_len,
        tls_server_name: ptr::null(),
        tls_server_name_len: 0,
        connect_timeout_ms: 0,
        reserved_end: 0,
    };
    let mut observed = Observed::default();
    let mut stack_config = config(record, &mut observed);
    (stack_config.bind_address, stack_config.bind_address_len) = text("127.0.0.1:0");
    let (status, stack) = create(&stack_config);
    assert_eq!(status, SipralStatus::Ok, "{}", last_error_text());
    assert_eq!(
        unsafe { sipral_network_start(stack, &raw const network, now(origin)) },
        SipralStatus::Ok,
        "{}",
        last_error_text()
    );
    let uri = format!("sips:{DOMAIN}");
    let aor = format!("sip:alice@{DOMAIN}");
    let registrar = format!("sip:{DOMAIN}");
    let mut line = account_config();
    (line.aor, line.aor_len) = text(&aor);
    (line.registrar, line.registrar_len) = text(&registrar);
    (line.contact, line.contact_len) = text("sip:alice@127.0.0.1;transport=tls");
    (line.registrar_address, line.registrar_address_len) = (ptr::null(), 0);
    (line.server_uri, line.server_uri_len) = text(&uri);
    line.stream_protocol = SipralTransport::Tls as u32;
    let mut account = SIPRAL_HANDLE_NONE;
    assert_eq!(
        unsafe { sipral_account_add(stack, &raw const line, &raw mut account) },
        SipralStatus::Ok
    );
    assert_eq!(
        unsafe { sipral_account_register(stack, account, now(origin)) },
        SipralStatus::Ok
    );
    run_until(stack, origin, "the refusal", || {
        !observed.transports_lost.is_empty()
    });
    let (transport, protocol, error, tls, detail) = observed.transports_lost[0].clone();
    assert!(
        transport >= 1 << 31,
        "a number of the component's: {transport}"
    );
    assert_eq!(protocol, 0, "a connection never made was never bound");
    assert_eq!(error, 2, "connection reset, as the bindings say it");
    assert_eq!(tls, 1, "untrusted: {detail}");
    assert!(detail.starts_with("TLS to 127.0.0.1:"), "{detail}");
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}

#[test]
fn a_configuration_that_cannot_be_read_says_which_member() {
    let mut observed = Observed::default();
    let mut stack_config = config(record, &mut observed);
    (stack_config.bind_address, stack_config.bind_address_len) = text("127.0.0.1:0");
    let (_, stack) = create(&stack_config);
    let broken = SipralNetworkConfig {
        size: size_of::<SipralNetworkConfig>(),
        trust: super::SipralNetworkTrust::OnlyAuthority as u32,
        reserved: 0,
        authority_pem: ptr::null(),
        authority_pem_len: 0,
        pin_sha256: ptr::null(),
        pin_sha256_len: 0,
        client_certificate_pem: ptr::null(),
        client_certificate_pem_len: 0,
        client_key_pem: ptr::null(),
        client_key_pem_len: 0,
        name_servers: ptr::null(),
        name_servers_len: 0,
        tls_server_name: ptr::null(),
        tls_server_name_len: 0,
        connect_timeout_ms: 0,
        reserved_end: 0,
    };
    assert_eq!(
        unsafe { sipral_network_start(stack, &raw const broken, 0) },
        SipralStatus::InvalidArgument
    );
    assert!(
        last_error_text().contains("authority_pem"),
        "{}",
        last_error_text()
    );
    assert_eq!(
        unsafe { sipral_network_run(stack, 0, 0) },
        SipralStatus::WrongState,
        "nothing runs before a start"
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);

    // a stack the component cannot run: its socket on a wildcard address
    let mut observed = Observed::default();
    let mut stack_config = config(record, &mut observed);
    (stack_config.bind_address, stack_config.bind_address_len) = text("0.0.0.0:0");
    let (_, stack) = create(&stack_config);
    assert_eq!(
        unsafe { sipral_network_start(stack, ptr::null(), 0) },
        SipralStatus::WrongState
    );
    assert!(
        last_error_text().contains("bind_address"),
        "{}",
        last_error_text()
    );
    assert_eq!(unsafe { sipral_stack_destroy(stack) }, SipralStatus::Ok);
}
