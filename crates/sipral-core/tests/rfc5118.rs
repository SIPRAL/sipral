// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! The RFC 5118 IPv6 torture corpus, run against the message layer.
//!
//! `fixtures/rfc5118/manifest.toml` says whether each of the twelve messages
//! is to be accepted or refused. The first test holds the layer to that; the
//! rest check, one per message, the particular thing its section of the RFC
//! is about, so that a message accepted for the wrong reason still fails.
//!
//! "Refused" means what it means for the RFC 4475 corpus: the parser refuses
//! the bytes, or they parse and [`RawMessage::validate`] refuses a field. Both
//! are the stack answering 400.
//!
//! The files are the RFC's archive as it is, and the archive is not quite a
//! set of messages as they travel: its lines end in a bare LF, two messages
//! stop without the empty line that ends a header section, and two of the
//! three bodies are not the length their `Content-Length` says. [`wire`]
//! turns each file into the message it describes — CRLF line ends, the
//! header section closed, `Content-Length` counted from the body — and
//! changes nothing else, so every test below is about IPv6 and none about
//! how the archive was made.

// a test says what it means; the no-panic discipline is for the library
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "this is a test binary, not the library"
)]

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

use sipral_core::auth::DigestAlgorithm;
use sipral_core::msg::{
    Contacts, HostRef, NameAddrRef, OwnedMessage, ParseMode, ParseScratch, RawMessage, SipUriRef,
    UriError, parse,
};
use sipral_core::sdp;

struct Entry {
    name: String,
    section: String,
    file: String,
    outcome: String,
    sha256: String,
}

fn fixtures() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/sipral-core
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("fixtures/rfc5118")
}

/// Read the `[[message]]` blocks: quoted values on lines of their own, as in
/// the RFC 4475 manifest.
fn manifest() -> Vec<Entry> {
    let text = fs::read_to_string(fixtures().join("manifest.toml")).expect("the manifest");
    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == "[[message]]" {
            entries.extend(current.take());
            current = Some(Entry {
                name: String::new(),
                section: String::new(),
                file: String::new(),
                outcome: String::new(),
                sha256: String::new(),
            });
            continue;
        }
        let Some(entry) = current.as_mut() else {
            continue;
        };
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim().trim_matches('"').to_owned();
        match key.trim() {
            "name" => entry.name = value,
            "section" => entry.section = value,
            "file" => entry.file = value,
            "outcome" => entry.outcome = value,
            "sha256" => entry.sha256 = value,
            _ => {}
        }
    }
    entries.extend(current);
    entries
}

/// A message from the archive, as it would arrive: every line ended with
/// CRLF as RFC 3261 §7 has it, the header section closed by an empty line,
/// and `Content-Length` the length of the body.
fn wire(archived: &[u8]) -> Vec<u8> {
    let text = std::str::from_utf8(archived).expect("the archive is text");
    let lines: Vec<&str> = text.split('\n').collect();
    let (head, body) = match lines.iter().position(|line| line.is_empty()) {
        Some(blank) => (&lines[..blank], &lines[blank + 1..]),
        None => (&lines[..], &[][..]),
    };
    // the last element after a final LF is empty, not a line
    let body = body.strip_suffix(&[""]).unwrap_or(body);
    let body: String = body.iter().flat_map(|line| [*line, "\r\n"]).collect();
    let mut out = String::new();
    for line in head.iter().filter(|line| !line.is_empty()) {
        if line.to_ascii_lowercase().starts_with("content-length:") {
            out.push_str("Content-Length: ");
            out.push_str(&body.len().to_string());
            out.push_str("\r\n");
        } else {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str("\r\n");
    out.push_str(&body);
    out.into_bytes()
}

fn archived(name: &str) -> Vec<u8> {
    fs::read(fixtures().join(format!("{name}.dat"))).expect("a fixture")
}

fn bytes_of(name: &str) -> Vec<u8> {
    wire(&archived(name))
}

/// What the stack would do with this message: `Ok` for accepted, the reason
/// otherwise.
fn judge(bytes: &[u8]) -> Result<(), String> {
    let mut scratch = ParseScratch::new();
    let message =
        parse(bytes, &mut scratch, ParseMode::Strict).map_err(|e| format!("parse: {e}"))?;
    message.validate().map_err(|e| format!("validate: {e}"))
}

/// Parse a message the manifest says is good, and keep it.
fn accepted(name: &str) -> OwnedMessage {
    let bytes = bytes_of(name);
    let mut scratch = ParseScratch::new();
    let message = parse(&bytes, &mut scratch, ParseMode::Strict).expect("parses");
    message.validate().expect("validates");
    message.to_owned()
}

fn request_uri<'a>(message: &RawMessage<'a>) -> SipUriRef<'a> {
    message
        .request_uri()
        .expect("a request")
        .expect("a URI")
        .sip()
        .expect("a SIP URI")
}

fn first_contact<'a>(message: &RawMessage<'a>) -> NameAddrRef<'a> {
    match message.contact().expect("a Contact") {
        Contacts::Addrs(mut addrs) => addrs.next().expect("one").expect("well formed"),
        Contacts::Star => panic!("an address, not a star"),
    }
}

fn v6(s: &str) -> Ipv6Addr {
    s.parse().expect("an IPv6 address")
}

#[test]
fn the_corpus_behaves_as_the_manifest_says() {
    let entries = manifest();
    assert_eq!(entries.len(), 12, "the manifest lost a message");

    let mut failures = Vec::new();
    for entry in &entries {
        let bytes = wire(
            &fs::read(fixtures().join(&entry.file))
                .unwrap_or_else(|e| panic!("reading {}: {e}", entry.file)),
        );
        let where_ = format!("{} (§{}, {})", entry.name, entry.section, entry.outcome);
        match (entry.outcome.as_str(), judge(&bytes)) {
            ("accept", Err(why)) => failures.push(format!("{where_}: refused, {why}")),
            ("reject", Ok(())) => failures.push(format!("{where_}: accepted")),
            ("accept" | "reject", _) => {}
            (other, _) => failures.push(format!("{where_}: unknown outcome {other}")),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn every_file_is_the_one_the_manifest_hashed() {
    // the archive's bytes, LF line ends and all; a checkout that converts
    // them fails here rather than quietly testing other messages
    for entry in manifest() {
        let bytes = fs::read(fixtures().join(&entry.file)).expect("a fixture");
        assert_eq!(
            DigestAlgorithm::Sha256.hash(&bytes),
            entry.sha256,
            "{} has changed",
            entry.file
        );
        assert!(!bytes.contains(&b'\r'), "{} has a CR", entry.file);
    }
}

#[test]
fn the_groups_are_the_sizes_the_rfc_has() {
    // RFC 5118 has one message to refuse, §4.2's; §4.10's three colons are
    // to be tolerated
    let entries = manifest();
    let count = |outcome: &str| entries.iter().filter(|e| e.outcome == outcome).count();
    assert_eq!(count("accept"), 11);
    assert_eq!(count("reject"), 1);
}

#[test]
fn the_archive_disagrees_with_itself_where_wire_says() {
    // the printed Content-Length, and the body as archived, of the three
    // messages with a body: §4.9 agrees, §4.6 and §4.8 do not
    for (name, printed, body) in [
        ("ipv6-in-sdp", 268, 242),
        ("mult-ip-in-sdp", 181, 180),
        ("ipv4-mapped-ipv6", 236, 236),
    ] {
        let text = String::from_utf8(archived(name)).expect("text");
        let (head, archived_body) = text.split_once("\n\n").expect("a body");
        assert!(
            head.contains(&format!("Content-Length: {printed}")),
            "{name}"
        );
        assert_eq!(archived_body.len(), body, "{name}");
        // on the wire, with CRLF, the body is one octet a line longer, and
        // Content-Length says so
        let lines = archived_body.matches('\n').count();
        let sent = String::from_utf8(wire(&archived(name))).expect("text");
        assert!(
            sent.contains(&format!("Content-Length: {}\r\n", body + lines)),
            "{name}"
        );
    }
    // two messages end without the empty line that closes a header section
    for name in ["ipv6-bug-abnf-3-colons", "ipv6-correct-abnf-2-colons"] {
        assert!(!archived(name).ends_with(b"\n\n"), "{name}");
        assert!(wire(&archived(name)).ends_with(b"\r\n\r\n"), "{name}");
    }
}

/// §4.1: an IPv6 reference in the Request-URI and in Contact.
#[test]
fn ipv6_good() {
    let owned = accepted("ipv6-good");
    let message = owned.as_raw();
    let uri = request_uri(&message);
    assert_eq!(uri.host, HostRef::Ipv6(v6("2001:db8::10")));
    assert_eq!(uri.port, None);

    let via = message.top_via().expect("a Via");
    assert_eq!(via.host, HostRef::Ipv6(v6("2001:db8::9:1")));

    let first = first_contact(&message);
    let contact_uri = first.uri().sip().expect("a SIP URI");
    assert_eq!(contact_uri.host, HostRef::Ipv6(v6("2001:db8::1")));
}

/// §4.2: the same address in the Request-URI without the brackets
/// RFC 3261 §19.1.1 requires. It has to be refused, and it has to be the
/// Request-URI that is refused.
#[test]
fn ipv6_bad() {
    let bytes = bytes_of("ipv6-bad");
    let why = judge(&bytes).expect_err("refused");
    assert!(why.contains("Request-URI"), "refused for {why}");

    let mut scratch = ParseScratch::new();
    let message = parse(&bytes, &mut scratch, ParseMode::Strict).expect("framing is fine");
    assert!(
        matches!(
            message.request_uri(),
            Some(Err(UriError::BadHost | UriError::BadPort))
        ),
        "{:?}",
        message.request_uri()
    );
}

/// §4.3: `[2001:db8::10:5070]` looks like an address and a port to a reader
/// who forgets the brackets. The brackets settle it: it is one address, and
/// there is no port.
#[test]
fn port_ambiguous() {
    let owned = accepted("port-ambiguous");
    let message = owned.as_raw();
    let uri = request_uri(&message);
    assert_eq!(uri.host, HostRef::Ipv6(v6("2001:db8::10:5070")));
    assert_eq!(uri.port, None);
}

/// §4.4: `[2001:db8::10]:5070` is an address and a port.
#[test]
fn port_unambiguous() {
    let owned = accepted("port-unambiguous");
    let message = owned.as_raw();
    let uri = request_uri(&message);
    assert_eq!(uri.host, HostRef::Ipv6(v6("2001:db8::10")));
    assert_eq!(uri.port, Some(5070));
}

/// §4.5: `received` written with the brackets of an IPv6 reference, which
/// RFC 3261's grammar leaves out and implementations send anyway.
#[test]
fn via_received_param_with_delim() {
    let owned = accepted("via-received-param-with-delim");
    let message = owned.as_raw();
    let via = message.top_via().expect("a Via");
    assert_eq!(via.received(), Some(IpAddr::V6(v6("2001:db8::9:255"))));
    assert_eq!(via.host, HostRef::Ipv6(v6("2001:db8::9:1")));
}

/// §4.5: `received` written bare, as RFC 3261's grammar has it.
#[test]
fn via_received_param_no_delim() {
    let owned = accepted("via-received-param-no-delim");
    let message = owned.as_raw();
    let via = message.top_via().expect("a Via");
    assert_eq!(via.received(), Some(IpAddr::V6(v6("2001:db8::9:255"))));
    // the parameter after it is still read: the colons inside the bare
    // address did not end the parameter list early
    assert_eq!(via.branch().as_deref(), Some(&b"z9hG4bKas3"[..]));
}

/// The SDP body of a message, parsed.
fn body_of(owned: &OwnedMessage) -> sdp::SessionDescription {
    let message = owned.as_raw();
    assert!(
        message
            .content_type()
            .expect("a Content-Type")
            .is("application", "sdp")
    );
    sdp::parse(message.body()).expect("the body is SDP")
}

/// §4.6: the body speaks IPv6 as well as the headers do.
#[test]
fn ipv6_in_sdp() {
    let owned = accepted("ipv6-in-sdp");
    let body = body_of(&owned);
    assert_eq!(body.origin.address_type, "IP6");
    assert_eq!(body.origin.address, "2001:db8::20");
    assert_eq!(body.media.len(), 2);
    for media in &body.media {
        let connection = body.connection_of(media).expect("the session c=");
        assert_eq!(connection.address_type, "IP6");
        assert_eq!(connection.ip(), Some(IpAddr::V6(v6("2001:db8::20"))));
    }
}

/// §4.7: three Via values, IPv6 then IPv4 then IPv6 with an IPv4 `received`.
#[test]
fn mult_ip_in_header() {
    let owned = accepted("mult-ip-in-header");
    let message = owned.as_raw();
    let vias: Vec<_> = message.via().map(|v| v.expect("a Via")).collect();
    assert_eq!(vias.len(), 3);

    assert_eq!(vias[0].host, HostRef::Ipv6(v6("2001:db8::9:1")));
    assert_eq!(vias[0].port, Some(6050));
    assert_eq!(vias[1].host, HostRef::Ipv4(Ipv4Addr::new(192, 0, 2, 1)));
    assert_eq!(vias[1].port, None);
    assert_eq!(vias[2].transport, "TCP");
    assert_eq!(vias[2].host, HostRef::Ipv6(v6("2001:db8::9:255")));
    assert_eq!(
        vias[2].received(),
        Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 200)))
    );
}

/// §4.8: no session-level `c=`, and each stream on its own address family.
#[test]
fn mult_ip_in_sdp() {
    let owned = accepted("mult-ip-in-sdp");
    let body = body_of(&owned);
    assert!(body.connection.is_none(), "there is no session c=");
    assert_eq!(body.media.len(), 2);
    let audio = body.connection_of(&body.media[0]).expect("audio c=");
    assert_eq!(audio.ip(), Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
    let video = body.connection_of(&body.media[1]).expect("video c=");
    assert_eq!(video.address_type, "IP6");
    assert_eq!(video.ip(), Some(IpAddr::V6(v6("2001:db8::1"))));
}

/// §4.9: IPv4-mapped IPv6 addresses are IPv6 addresses, in the Via list, in
/// the Contact and in the body.
#[test]
fn ipv4_mapped_ipv6() {
    let owned = accepted("ipv4-mapped-ipv6");
    let message = owned.as_raw();
    let mapped = v6("::ffff:192.0.2.2");
    let vias: Vec<_> = message.via().map(|v| v.expect("a Via")).collect();
    assert_eq!(vias.len(), 2);
    assert_eq!(vias[0].host, HostRef::Ipv6(v6("::ffff:192.0.2.10")));
    assert_eq!(vias[0].port, Some(19823));
    assert_eq!(vias[1].host, HostRef::Ipv6(mapped));

    let first = first_contact(&message);
    assert_eq!(
        first.uri().sip().expect("a SIP URI").host,
        HostRef::Ipv6(mapped)
    );

    let body = body_of(&owned);
    let connection = body.connection.as_ref().expect("a session c=");
    assert_eq!(connection.address_type, "IP6");
    assert_eq!(connection.ip(), Some(IpAddr::V6(mapped)));
}

/// §4.10: RFC 3261's `IPv6address` production admits `2001:db8:::192.0.2.1`,
/// which RFC 4291 does not. "Following the Robustness Principle [RFC1122],
/// an implementation must tolerate both of the above constructs", reading
/// the address as if the extra colon were not there.
#[test]
fn ipv6_bug_abnf_3_colons() {
    let owned = accepted("ipv6-bug-abnf-3-colons");
    let message = owned.as_raw();
    let address = HostRef::Ipv6(v6("2001:db8::192.0.2.1"));
    let uri = request_uri(&message);
    assert_eq!(uri.user, Some("user"));
    assert_eq!(uri.host, address);
    assert_eq!(
        message.to().expect("To").uri().sip().expect("SIP").host,
        address
    );
}

/// §4.10: the same message with the address written correctly.
#[test]
fn ipv6_correct_abnf_2_colons() {
    let owned = accepted("ipv6-correct-abnf-2-colons");
    let message = owned.as_raw();
    let address = HostRef::Ipv6(v6("2001:db8::c000:201"));
    assert_eq!(request_uri(&message).host, address);
    assert_eq!(
        message.to().expect("To").uri().sip().expect("SIP").host,
        address
    );
    assert_eq!(
        message.from().expect("From").uri().sip().expect("SIP").host,
        HostRef::Name("example.com")
    );
}
