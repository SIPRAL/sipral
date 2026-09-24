// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea

//! Drives the `sipral` facade against the container lab and judges each flow.
//!
//! Every other test in this workspace runs the stack against a peer written in
//! the same file, or against a second copy of itself. Both prove it is
//! consistent; neither proves it is interoperable, because our idea of what a
//! registrar sends is our idea. This one talks to Kamailio, OpenSIPS,
//! FreeSWITCH and Asterisk as they ship, and the failures it finds are the
//! ones that would otherwise be found by a customer.
//!
//! Pass and fail are decided before the run, not looked at afterwards. Each
//! flow states what has to be true; a flow that is partly right is a failure
//! with the failing condition named, and the process exits non-zero so that
//! whoever ran `scripts/lab.sh` does not have to read the log to know.
//!
//! # Through the facade, not around it
//!
//! Until 8.5.1 this crate carried its own RTP session, its own codec pair and
//! its own DTMF sender — a second media join, written for the lab and used
//! nowhere else. `sipral::MediaEngine` and `sipral::MediaSession` are that
//! join now, for RTP, codecs, DTMF and SRTP alike; what is left here is what
//! any application still has to write for itself, because the facade owns
//! neither a socket nor a device: bind one, feed it datagrams, and drive the
//! loop. `crate::audio` is that remainder for the media socket;
//! [`Endpoint`] is it for the SIP one.

// tests say what they mean; the no-panic discipline is for what ships
#![cfg_attr(
    test,
    allow(
        clippy::panic,
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing
    )
)]

mod audio;
mod drift;
mod fork;
mod ice_lite;
mod ice_nat;
mod join;
#[cfg(test)]
mod local;
mod pair;
#[cfg(all(feature = "pipewire", target_os = "linux"))]
mod pipewire;
mod quality;
#[cfg(all(feature = "wasapi", target_os = "windows"))]
mod wasapi;

use std::collections::HashMap;
use std::env;
use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sipral::{
    Account, AccountId, CallHandle, CallMedia, CallState, Codec, CodecCatalog, Credentials,
    DEFAULT_DIGIT, Digit, DtmfInfoForm, EndpointConfig, Event, Input, MediaConfig, MediaEngine,
    MediaEvent, OutgoingCall, Quality, SrtpPolicy, StreamStatistics, Subscribe, TransportId,
    TransportProtocol, UNAVAILABLE, UaEvent, Uri, UserAgent, VoipMetricsBlock, WallClock,
};
use sipral_core::msg::{HeaderName, OwnedMessage};

use crate::audio::Media;

/// How long any one flow may take before it is a failure. Every step in these
/// flows is a round trip on a loopback bridge; a whole flow that needs more
/// than this has not gone slowly, it has gone wrong.
///
/// Both this and [`dwell`] are overridable, and one impairment profile needs
/// it: a link that disappears for eight seconds cannot be measured on a call
/// that lasts two.
fn patience() -> Duration {
    seconds_from("SIPRAL_PATIENCE_MS", 20_000)
}

/// How long a plain call stays up before it is hung up. Long enough for a
/// hundred frames each way, which is enough to tell a tone coming back from a
/// line that is merely open.
fn dwell() -> Duration {
    seconds_from("SIPRAL_DWELL_MS", 2_000)
}

fn seconds_from(name: &str, fallback: u64) -> Duration {
    Duration::from_millis(
        env::var(name)
            .ok()
            .and_then(|text| text.parse().ok())
            .unwrap_or(fallback),
    )
}

/// How long to wait for the far end to become transferable before asking
/// anyway.
///
/// A REFER sent the instant the dialog confirms reaches Asterisk before it has
/// put the channel into a bridge, and a transfer of a channel that is in no
/// bridge is answered `202` and then reported `400` in the sipfrag. Measured
/// on the lab's own Asterisk: the REFER was processed and the 400 sent 271
/// microseconds before the channel joined the bridge. Nothing is wrong with
/// the REFER — no phone sends one that fast, because a person has to press the
/// key. What proves the far end is bridged is audio arriving from it, so that
/// is what is waited for; this is only the cap, so that a server which sends
/// no audio still gets the REFER and the flow reports the transfer's own
/// outcome rather than a timeout.
const SETTLE: Duration = Duration::from_secs(1);

/// Audible frames `Flow::G729` has to hear back from the echo: half a second
/// of twenty-millisecond frames.
const G729_ECHOED: u32 = 25;

/// The digit `Flow::Dtmf4733` sends and expects back.
const TEST_DIGIT: Digit = Digit::Number(5);

/// `Flow::Message`'s own body. Not read back for a match — the lab's own
/// dialplan is free to prefix it on the way back (`interop/asterisk`'s own
/// extension 9006 does) — only that a MESSAGE came back at all.
const MESSAGE_BODY: &str = "sipral interop lab";

/// The codec order this harness offers, chosen by `SIPRAL_CODEC`.
///
/// Both laws, because offering one is not what a client does — the first real
/// PBX this stack met allows A-law only, which is the ordinary European
/// default, and answered 488 to an offer that carried only mu-law.
/// `sipral::CodecCatalog::new` would already put G.722 first in this build,
/// since Opus is off (see `Cargo.toml`) and `Codec::ALL` lists it first among
/// what is left — so the ordinary flows name their own order rather than
/// taking the default, and `SIPRAL_CODEC=g722` names a different one instead
/// of turning a flag on: every lab server here takes G.722 too, and folding
/// it into the ordinary offer would silently change what the other flows have
/// been proving for days.
fn catalog() -> CodecCatalog {
    let order: &[&str] = match env::var("SIPRAL_CODEC").as_deref() {
        Ok("g722") => &["G722", "PCMU", "PCMA"],
        _ => &["PCMU", "PCMA"],
    };
    // both orders name codecs this build always has, once each, so the only
    // way `with_order` refuses is a name misspelled right here; the fallback
    // exists so this stays a `CodecCatalog` and not a `panic!` and is never
    // actually taken
    CodecCatalog::with_order(order).unwrap_or_else(|_| CodecCatalog::new())
}

/// What `flow` places its call with: [`catalog`] for every flow except
/// [`Flow::Srtp`], [`Flow::Dtls`] and their own phone-to-phone counterparts
/// [`Flow::PeerSrtp`]/[`Flow::PeerDtls`], which are refused rather than
/// answered plainly if the far end turns out not to key the call — the whole
/// point of each is that the call runs under SDES, or under a DTLS-SRTP
/// handshake, or does not run at all.
///
/// [`Flow::G729`] offers G.729 alone: an offer with G.711 beside it would let
/// the far end pick the codec the other flows already prove, and the flow
/// would pass having proved nothing about this one.
fn catalog_for(flow: Flow) -> CodecCatalog {
    match flow {
        Flow::Srtp | Flow::PeerSrtp => catalog().with_srtp(SrtpPolicy::Required),
        Flow::Dtls | Flow::PeerDtls => catalog().with_srtp(SrtpPolicy::DtlsRequired),
        // this build always has G.729, so the fallback is never taken; it
        // keeps this a catalogue rather than a panic, like `catalog`'s own
        Flow::G729 => catalog()
            .with_codecs(&["G729"])
            .unwrap_or_else(|_| catalog()),
        _ => catalog(),
    }
}

/// Not a flow: interop/wasapi/run.ps1's own first step, to find the exact
/// endpoint a VB-CABLE installs under before pointing wasapi.rs's own
/// `SIPRAL_WASAPI_EARPIECE_ID` / `SIPRAL_WASAPI_MIC_ID` at it. Enumerates
/// whatever `sipral_io_wasapi::devices` says the machine has and nothing
/// else.
#[cfg(all(feature = "wasapi", target_os = "windows"))]
fn list_audio_devices() -> ExitCode {
    match sipral_io_wasapi::devices() {
        Ok(mut found) => {
            found.sort_by(|a, b| (a.direction, &a.name).cmp(&(b.direction, &b.name)));
            for device in &found {
                println!("{device}  [{}]", device.id);
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("cannot list audio endpoints: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    #[cfg(all(feature = "wasapi", target_os = "windows"))]
    if env::args().nth(1).as_deref() == Some("--list-audio-devices") {
        return list_audio_devices();
    }
    let server = env::args().nth(1).unwrap_or_else(|| "kamailio".to_owned());
    let port: u16 = env::args()
        .nth(2)
        .and_then(|text| text.parse().ok())
        .unwrap_or(5060);
    let extension = env::args().nth(3).unwrap_or_else(|| "9000".to_owned());
    let other = env::args().nth(4).unwrap_or_else(|| "9001".to_owned());

    // the lab's own account unless something else is named. A real server is
    // reached with real credentials, and those do not belong in a repository
    // that becomes public
    let user = env::var("SIPRAL_USER").unwrap_or_else(|_| "labuser".to_owned());
    let pass = env::var("SIPRAL_PASS").unwrap_or_else(|_| "labpass".to_owned());
    // the SDES endpoint's own identity (see interop/asterisk's own endpoint
    // config): a separate account so the plain `labuser` endpoint the other
    // five flows use is untouched by it
    let srtp_user = env::var("SIPRAL_USER_SRTP").unwrap_or_else(|_| "labuser-srtp".to_owned());
    let srtp_pass = env::var("SIPRAL_PASS_SRTP").unwrap_or_else(|_| pass.clone());
    // the endpoint 8.3.11 added for INFO's own dtmf_mode (interop/asterisk's
    // `labuser-infodtmf`), kept apart from `labuser` for the same reason the
    // SDES one is
    let infodtmf_user =
        env::var("SIPRAL_USER_INFODTMF").unwrap_or_else(|_| "labuser-infodtmf".to_owned());
    let infodtmf_pass = env::var("SIPRAL_PASS_INFODTMF").unwrap_or_else(|_| pass.clone());
    // and the DTLS-SRTP endpoint's (interop/asterisk's `labuser-dtls`), for
    // the same reason again
    let dtls_user = env::var("SIPRAL_USER_DTLS").unwrap_or_else(|_| "labuser-dtls".to_owned());
    let dtls_pass = env::var("SIPRAL_PASS_DTLS").unwrap_or_else(|_| pass.clone());
    // 8.6.5's mailbox endpoint (interop/asterisk's `labuser-mwi`), kept apart
    // from `labuser` for the same reason the SDES one is: it is the one
    // account whose AOR has `mailboxes=9007@default`
    let mwi_user = env::var("SIPRAL_USER_MWI").unwrap_or_else(|_| "labuser-mwi".to_owned());
    let mwi_pass = env::var("SIPRAL_PASS_MWI").unwrap_or_else(|_| pass.clone());
    // the G.729 endpoint (interop/asterisk's `labuser-g729`), the only one
    // that allows the codec, so every other flow's offer is answered as it
    // always was
    let g729_user = env::var("SIPRAL_USER_G729").unwrap_or_else(|_| "labuser-g729".to_owned());
    let g729_pass = env::var("SIPRAL_PASS_G729").unwrap_or_else(|_| pass.clone());
    let wanted = env::var("SIPRAL_FLOWS").unwrap_or_default();

    let Some(remote) = resolve(&server, port) else {
        println!("cannot resolve {server}:{port}");
        return ExitCode::FAILURE;
    };
    println!("lab: {server}:{port} at {remote}, extension {extension}, as {user}");

    let mut flows = vec![
        Flow::Register,
        Flow::Call,
        Flow::Hold,
        Flow::Blind,
        Flow::Attended,
    ];
    // this lab's own SDES endpoint and codec-change dialplan exist only on
    // Asterisk; see `docs/11-testing.md` for why they are not on FreeSWITCH
    // or through the proxy. The DTMF check runs there too, for now: the digit
    // Asterisk names back never came back through the proxy from FreeSWITCH,
    // and a flow is not run where it is known not to pass until the reason is
    // found
    if server == "asterisk" {
        flows.push(Flow::Dtmf4733);
        flows.push(Flow::DtmfInfo);
        flows.push(Flow::Srtp);
        flows.push(Flow::HoldCodecChange);
        flows.push(Flow::Message);
        flows.push(Flow::Mwi);
        flows.push(Flow::G729);
    }
    // DTLS-SRTP on both: interop/freeswitch/lab.xml answers 9005 too
    flows.push(Flow::Dtls);
    // the phone-to-phone peer: gated on SIPRAL_PEER rather than on
    // `server`, because this run and the plain kamailio one above both name
    // "kamailio" as their server — that is the proxy's own address either
    // way — and only this one may dial an account interop/asterisk and
    // interop/freeswitch know nothing about. scripts/lab.sh sets it only for
    // its own "baresip" step, so neither of the ordinary runs ever pushes
    // these two.
    if env::var("SIPRAL_PEER").as_deref() == Ok("baresip") {
        flows.push(Flow::PeerSrtp);
        flows.push(Flow::PeerDtls);
    }

    let mut failures = 0;
    for flow in flows {
        if !wanted.is_empty() && !wanted.split(',').any(|name| name.trim() == flow.key()) {
            continue;
        }
        let (this_user, this_pass) = match flow {
            Flow::Srtp => (srtp_user.as_str(), srtp_pass.as_str()),
            Flow::DtmfInfo => (infodtmf_user.as_str(), infodtmf_pass.as_str()),
            // Asterisk's own DTLS endpoint; the proxy knows only the one user,
            // and FreeSWITCH behind it decides per extension, not per account
            Flow::Dtls if server == "asterisk" => (dtls_user.as_str(), dtls_pass.as_str()),
            Flow::Mwi => (mwi_user.as_str(), mwi_pass.as_str()),
            Flow::G729 => (g729_user.as_str(), g729_pass.as_str()),
            _ => (user.as_str(), pass.as_str()),
        };
        match run(
            flow, &server, remote, &extension, &other, this_user, this_pass,
        ) {
            Ok(media) => println!("  pass  {}{media}", flow.name()),
            Err(why) => {
                println!("  FAIL  {} — {why}", flow.name());
                failures += 1;
            }
        }
    }
    failures += extra_flows(&server, remote, (&user, &pass), &extension, &wanted);

    if failures == 0 {
        println!("every flow passed");
        return ExitCode::SUCCESS;
    }
    println!("{failures} flow(s) failed");
    ExitCode::FAILURE
}

/// Everything `main` runs beyond the `Flow` table: two calls on one account,
/// which `run` has no shape for, and the flows whose audio is a real
/// device's, each gated on its own platform and feature. Split out of
/// `main` itself only to keep that function's own length sane — every one
/// of these keeps the gating and the pass/fail printing `main` used to do
/// inline.
///
/// Returns how many of them failed.
fn extra_flows(
    server: &str,
    remote: SocketAddr,
    (user, pass): (&str, &str),
    extension: &str,
    wanted: &str,
) -> u32 {
    let mut failures = 0;
    // a call that requires ICE, straight at the peer `server` names rather
    // than through a registrar: only when named, since only
    // `scripts/lab.sh`'s ICE steps start a peer for it (see `ice_lite`)
    if wanted.split(',').any(|name| name.trim() == "icelite") {
        match ice_lite::run(extension, remote) {
            Ok(said) => println!("  pass  ICE required, against {server}{said}"),
            Err(why) => {
                println!("  FAIL  ICE required, against {server} — {why}");
                failures += 1;
            }
        }
    }
    // the two halves of a call between two stacks behind two NATs, each run
    // in a container of its own behind its NAT (see `ice_nat`): `server` is
    // the callee's NAT for the caller, and the STUN server for the callee
    if wanted.split(',').any(|name| name.trim() == "icenat") {
        match ice_nat::call(extension, remote) {
            Ok(said) => println!("  pass  full ICE through two NATs, calling{said}"),
            Err(why) => {
                println!("  FAIL  full ICE through two NATs, calling — {why}");
                failures += 1;
            }
        }
    }
    if wanted.split(',').any(|name| name.trim() == "iceanswer") {
        match ice_nat::answer(remote) {
            Ok(said) => println!("  pass  full ICE through two NATs, answering{said}"),
            Err(why) => {
                println!("  FAIL  full ICE through two NATs, answering — {why}");
                failures += 1;
            }
        }
    }
    // only when a second account is named: it needs two registrations on the
    // same server, and one of them has to have been left with a wide codec list
    if let (Ok(wide_user), Ok(wide_pass)) =
        (env::var("SIPRAL_USER_WIDE"), env::var("SIPRAL_PASS_WIDE"))
        && (wanted.is_empty() || wanted.split(',').any(|name| name.trim() == "inbound"))
    {
        match pair::run(server, remote, &wide_user, &wide_pass, user, pass) {
            Ok(said) => println!("  pass  inbound, narrowed{said}"),
            Err(why) => {
                println!("  FAIL  inbound, narrowed — {why}");
                failures += 1;
            }
        }
    }
    // one call forked by the proxy to two phones registered as one user, the
    // second answering first (see `fork`): only through Kamailio, whose config
    // forks that user and nobody else, and only in a run that names no flow
    // or names this one — the phone-to-phone and bad-network runs also say
    // "kamailio", and name their own flows
    if server == "kamailio"
        && (wanted.is_empty() || wanted.split(',').any(|name| name.trim() == "fork"))
    {
        match fork::run(server, remote) {
            Ok(said) => println!("  pass  forked, the second phone answering first{said}"),
            Err(why) => {
                println!("  FAIL  forked, the second phone answering first — {why}");
                failures += 1;
            }
        }
    }
    // this lab's own echo extension (interop/asterisk's 9008) exists only on
    // Asterisk, the same reason the SDES and codec-change flows are gated
    // above — two calls placed on one account, which `run` above has no shape
    // for, so this is driven the same way `pair::run` is rather than through
    // `Flow`
    if server == "asterisk"
        && (wanted.is_empty() || wanted.split(',').any(|name| name.trim() == "join"))
    {
        match join::run(server, remote, user, pass) {
            Ok(said) => println!("  pass  local conference{said}"),
            Err(why) => {
                println!("  FAIL  local conference — {why}");
                failures += 1;
            }
        }
    }
    // an hour on three calls to the same echo, and only when named: nothing
    // that runs by default may take an hour (see `drift`)
    if server == "asterisk" && wanted.split(',').any(|name| name.trim() == "drift") {
        match drift::run(server, remote, user, pass) {
            Ok(said) => println!("  pass  an hour of drift{said}"),
            Err(why) => {
                println!("  FAIL  an hour of drift — {why}");
                failures += 1;
            }
        }
    }
    // PipeWire's devices, and only when named: see `pipewire::flow`
    #[cfg(all(feature = "pipewire", target_os = "linux"))]
    if !pipewire::flow(server, remote, user, pass, wanted) {
        failures += 1;
    }
    // WASAPI's devices, and only when named: see `wasapi::flow`
    #[cfg(all(feature = "wasapi", target_os = "windows"))]
    if !wasapi::flow(server, remote, user, pass, wanted) {
        failures += 1;
    }
    failures
}

/// One scripted exchange, with what has to be true for it to have passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flow {
    /// A binding taken, and given back.
    Register,
    /// A call placed, answered, and hung up.
    Call,
    /// The same, put on hold and taken off it again.
    Hold,
    /// A call handed to somebody else without asking them first (RFC 3515).
    Blind,
    /// A call handed over after speaking to the person taking it, so the
    /// REFER names the dialog to replace (RFC 3891).
    Attended,
    /// A digit sent as an RFC 4733 named telephone event, echoed back by the
    /// lab's own dialplan (interop/asterisk/extensions.conf,
    /// interop/freeswitch/lab.xml) so this end can tell the exact digit
    /// crossed rather than merely that something did.
    Dtmf4733,
    /// The same digit, sent as a SIP INFO instead (8.3.11), against
    /// Asterisk's own `labuser-infodtmf` endpoint (interop/asterisk's own
    /// endpoint config) so `SendDTMF()`'s own echo goes back over INFO too
    /// and this end's receiving half is exercised against a real peer as
    /// well as its sending one.
    DtmfInfo,
    /// A call placed with SDES required, against the lab's own SRTP endpoint
    /// (interop/asterisk's own `labuser-srtp`).
    Srtp,
    /// A held call moved onto a narrower codec list while it stays held, and
    /// then resumed on it (the 8.2.1 case): the far end's answer to the
    /// change names a different codec than the one the call held on, and the
    /// resume keeps it.
    HoldCodecChange,
    /// A call keyed by a DTLS-SRTP handshake on the media path (RFC 5764),
    /// against the lab's own DTLS endpoint (interop/asterisk's own
    /// `labuser-dtls`), heard, held, resumed and heard again. The hold and the
    /// resume are both re-offers, which hand the DTLS roles back with
    /// `actpass` (RFC 8842 §5.5); audio after the resume is what says the far
    /// end answered them with the roles already in force (§5.3) and the
    /// association the call was keyed by is still the one carrying it.
    Dtls,
    /// 8.6.5's MESSAGE flow (RFC 3428): an out-of-dialog MESSAGE sent to the
    /// lab's own echo extension (interop/asterisk's own extension 9006),
    /// which answers it with a MESSAGE of its own back to whoever sent it.
    /// This end sees both: its own send answered with success, and the
    /// echo arriving as `UaEvent::MessageReceived`.
    Message,
    /// 8.6.5's message waiting indication flow (RFC 3842): a subscription to
    /// `message-summary` for this account's own mailbox, a call placed into
    /// the lab's own mailbox extension (interop/asterisk's own extension
    /// 9007, which announces a new message when the call ends), and the
    /// mailbox's `new` count read back higher once Asterisk's own MWI
    /// support reports it.
    Mwi,
    /// [`Flow::Srtp`] again, against the lab's phone-to-phone peer
    /// instead of a server: SDES required against baresip's own
    /// `baresip-srtp` account (`interop/baresip/config/accounts`), refused
    /// rather than answered plainly if that peer will not key it either.
    PeerSrtp,
    /// [`Flow::Dtls`] again, against the same peer's `baresip-dtls`
    /// account: a third independent DTLS-SRTP implementation, after
    /// Asterisk's and FreeSWITCH's, on the far side of a call this stack
    /// placed rather than one it answered.
    PeerDtls,
    /// A call offering G.729 and nothing else, as Asterisk's own
    /// `labuser-g729` (the one endpoint that allows it), to the lab's echo
    /// extension (9008): the tone this end's G.729 encoder writes goes to
    /// Asterisk and comes back, and this end's decoder has to hear it. The
    /// lab's Asterisk carries no G.729 translator, so it cannot have decoded
    /// and re-encoded the frames on the way — what comes back is what this
    /// end sent, handed back by `Echo()` on a channel that is G.729 at both
    /// ends.
    G729,
}

impl Flow {
    const fn name(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Call => "call",
            Self::Hold => "hold and resume",
            Self::Blind => "blind transfer",
            Self::Attended => "attended transfer",
            Self::Dtmf4733 => "DTMF, RFC 4733",
            Self::DtmfInfo => "DTMF, SIP INFO",
            Self::Srtp => "SRTP",
            Self::HoldCodecChange => "hold with a codec change",
            Self::Dtls => "DTLS-SRTP, held and resumed",
            Self::Message => "MESSAGE, echoed",
            Self::Mwi => "message waiting indication",
            Self::PeerSrtp => "SRTP, phone to phone",
            Self::PeerDtls => "DTLS-SRTP, phone to phone",
            Self::G729 => "G.729, echoed",
        }
    }

    /// The name `SIPRAL_FLOWS` selects it by.
    const fn key(self) -> &'static str {
        match self {
            Self::Register => "register",
            Self::Call => "call",
            Self::Hold => "hold",
            Self::Blind => "blind",
            Self::Attended => "attended",
            Self::Dtmf4733 => "dtmf",
            Self::DtmfInfo => "dtmfinfo",
            Self::Srtp => "srtp",
            Self::HoldCodecChange => "holdcodec",
            Self::Dtls => "dtls",
            Self::Message => "message",
            Self::Mwi => "mwi",
            Self::PeerSrtp => "peersrtp",
            Self::PeerDtls => "peerdtls",
            Self::G729 => "g729",
        }
    }
}

/// One thing that happened. A set of these rather than a pile of flags,
/// because the verdict is read off them at the end and a flag that can be set
/// twice is a flag that can lie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Fact {
    Registered,
    Unregistered,
    Ringing,
    Up,
    Held,
    Resumed,
    /// The second call of an attended transfer is up.
    Consulted,
    /// The far end reported the transfer under way, in a sipfrag.
    Transferring,
    /// And reported it finished, with a status that says it worked.
    Transferred,
    /// The digit this end sent came back named the same way, on the same
    /// call.
    DigitConfirmed,
    /// `Flow::DtmfInfo`'s own INFO reached a final answer that says the far
    /// end took it.
    DigitSent,
    /// The session is actually running under the keys it negotiated: SDES
    /// ones from the description, or a DTLS-SRTP handshake that finished.
    Encrypted,
    /// The codec running after the resume differs from the one running
    /// during the hold.
    CodecChanged,
    /// We asked for the call to end, rather than watching it end by itself.
    Ours,
    Over,
    /// `Flow::Message`'s own MESSAGE was answered 200 or 202.
    MessageAccepted,
    /// The lab's own echo dialplan sent a MESSAGE back.
    MessageEchoed,
    /// `Flow::Mwi`'s subscription to `message-summary` was granted.
    Subscribed,
    /// The mailbox's `new` count read higher after the voicemail was left
    /// than it did at the subscription's first notification.
    MailboxCounted,
}

/// What the run has seen. The conditions are read off this at the end, so that
/// a flow which did three of four things is a failure naming the fourth rather
/// than a pass.
#[derive(Debug, Default)]
struct Seen {
    facts: std::collections::HashSet<Fact>,
    refused: Option<String>,
}

impl Seen {
    fn saw(&mut self, fact: Fact) {
        self.facts.insert(fact);
    }

    fn has(&self, fact: Fact) -> bool {
        self.facts.contains(&fact)
    }
}

/// A user agent and a media engine with real sockets under them.
///
/// This is the whole of what replaces `sipral_ua::Runtime` here:
/// `MediaEngine::poll_event` is the one place events may be drained from —
/// its own documentation says so — so the reference loop's own drain, which
/// knows nothing of media, cannot sit in front of it. What is left is small:
/// one SIP socket, one RTP socket per call with a session running on it, and
/// a loop that flushes, drains, plays, and reads.
struct Endpoint {
    agent: UserAgent,
    engine: MediaEngine,
    sip: UdpSocket,
    local: SocketAddr,
    transport: TransportId,
    /// One RTP socket per call that has media, opened before the call is
    /// placed or answered so its port can go in the offer or the answer.
    media: HashMap<CallHandle, Media>,
    /// The SIP socket's own read buffer, kept here rather than on the stack
    /// of [`Endpoint::read_sip`], which every one of this loop's turns calls.
    sip_inbox: Vec<u8>,
}

impl Endpoint {
    /// Bind the SIP socket, start a user agent on it, and open a media
    /// engine that will offer `catalog`.
    ///
    /// # Errors
    /// Whatever binding the socket or starting the user agent returns.
    fn bind(
        seed: [u8; 32],
        media_seed: [u8; 32],
        bind_addr: SocketAddr,
        catalog: CodecCatalog,
        now: Instant,
    ) -> Result<Self, String> {
        let sip = UdpSocket::bind(bind_addr).map_err(|error| format!("cannot bind: {error}"))?;
        sip.set_nonblocking(true)
            .map_err(|error| format!("cannot make the SIP socket non-blocking: {error}"))?;
        let local = sip
            .local_addr()
            .map_err(|error| format!("the SIP socket has no address: {error}"))?;
        let transport = TransportId(1);
        let mut agent = UserAgent::new(EndpointConfig::default(), seed)
            .map_err(|error| format!("cannot start a user agent: {error}"))?;
        agent
            .receive(
                Input::TransportBound {
                    transport,
                    protocol: TransportProtocol::Udp,
                    local,
                    remote: None,
                },
                now,
            )
            .map_err(|error| format!("cannot bind the transport: {error}"))?;
        let unix_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let engine = MediaEngine::new(
            catalog,
            MediaConfig::default(),
            WallClock::from_unix(now, unix_seconds, 0),
            media_seed,
        );
        Ok(Self {
            agent,
            engine,
            sip,
            local,
            transport,
            media: HashMap::new(),
            sip_inbox: vec![0_u8; 65_535],
        })
    }

    fn account(
        &mut self,
        user: &str,
        pass: &str,
        server: &str,
        remote: SocketAddr,
    ) -> Result<AccountId, String> {
        let aor = uri(&format!("sip:{user}@{server}"))?;
        let registrar = uri(&format!("sip:{server}"))?;
        let contact = uri(&format!("sip:{user}@{}", advertised(self.local, remote)))?;
        Ok(self.agent.add_account(
            Account::new(aor, registrar, contact, self.transport, remote)
                .credentials(Credentials::new(user, pass))
                .expires(Duration::from_secs(300)),
        ))
    }

    /// Bind a fresh RTP socket for a call about to be placed or answered, and
    /// say where the offer or the answer should send media.
    fn open_media(
        &mut self,
        call: CallHandle,
        remote: SocketAddr,
        now: Instant,
    ) -> Result<SocketAddr, String> {
        let media = Media::bind(now)?;
        let port = media.port()?;
        self.media.insert(call, media);
        Ok(SocketAddr::new(route_to(remote), port))
    }

    /// Write what is waiting, and drain every event the engine has — which
    /// drains the agent too, since [`MediaEngine::poll_event`]'s own
    /// documentation makes it the one place that may. Returned rather than
    /// handed to a callback, so this is the same pump for `main`'s flow
    /// script and `pair`'s two roles, which react to events differently.
    fn pump(&mut self, now: Instant) -> Vec<Event> {
        self.flush();
        let mut events = Vec::new();
        while let Some(event) = self.engine.poll_event(&mut self.agent, now) {
            events.push(event);
        }
        events
    }

    /// Write every SIP message the agent has queued.
    fn flush(&mut self) {
        while let Some(transmit) = self.agent.poll_transmit() {
            let _ = self.sip.send_to(&transmit.payload, transmit.destination);
        }
    }

    /// Run every active call's media for one tick, and carry whatever the
    /// engine had queued to send on its behalf.
    fn run_media(&mut self, now: Instant) {
        for call in self.engine.active().collect::<Vec<_>>() {
            let Some(mut session) = self.engine.session(call) else {
                continue;
            };
            if let Some(media) = self.media.get_mut(&call) {
                media.turn(&mut session, now);
            }
        }
        while let Some((call, destination, payload)) = self.engine.poll_rtcp(now) {
            if let Some(media) = self.media.get(&call) {
                media.send(destination, &payload);
            }
        }
        while let Some((call, destination, payload)) = self.engine.poll_farewell() {
            if let Some(media) = self.media.get(&call) {
                media.send(destination, &payload);
            }
        }
        // the DTLS-SRTP handshake's records, which are how `Flow::Dtls` gets
        // any keys at all: a ClientHello left in here is a call that comes up
        // and never carries a frame
        while let Some((call, destination, payload)) = self.engine.poll_transmit(now) {
            if let Some(media) = self.media.get(&call) {
                media.send(destination, &payload);
            }
        }
    }

    fn timers(&mut self, now: Instant) {
        self.engine.handle_timeout(now);
        self.agent.handle_timeout(now);
    }

    /// Read whatever SIP datagrams have arrived, non-blockingly. `true` when
    /// at least one did.
    fn read_sip(&mut self, now: Instant) -> bool {
        let mut arrived = false;
        loop {
            match self.sip.recv_from(&mut self.sip_inbox) {
                Ok((length, from)) => {
                    arrived = true;
                    let data = self.sip_inbox.get(..length).unwrap_or_default();
                    let _ = self.agent.receive(
                        Input::Datagram {
                            transport: self.transport,
                            remote: from,
                            local: self.local,
                            data,
                        },
                        now,
                    );
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        arrived
    }
}

/// Round the loop until the script is done or `deadline` passes.
fn drive(endpoint: &mut Endpoint, script: &mut Script, deadline: Instant) {
    loop {
        let now = Instant::now();
        for event in endpoint.pump(now) {
            script.on_event(endpoint, &event, now);
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        script.on_tick(endpoint, now);
        if script.step == Step::Done || now > deadline {
            // the event that finished the flow has usually just queued its
            // last request — the binding given back, or a BYE — and nothing
            // after this loop is left to write it out
            endpoint.flush();
            return;
        }
        // no reader thread here, unlike `sipral_ua::Runtime`: this loop is
        // its own, and a short sleep after a quiet read is what keeps it from
        // spinning a whole core for the twenty seconds patience() allows
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

struct Script {
    flow: Flow,
    account: AccountId,
    extension: String,
    /// Who a transfer hands the call to.
    other: String,
    server: String,
    remote: SocketAddr,
    started: Instant,
    seen: Seen,
    call: Option<CallHandle>,
    /// The second leg of an attended transfer.
    consulted: Option<CallHandle>,
    /// What the primary call settled on when it first came up, kept so
    /// `Flow::HoldCodecChange` can tell whether the change actually moved it.
    original_codec: Option<Codec>,
    /// What the primary call's media cost, from the `MediaEvent::Ended` that
    /// closed it: by the time a flow is judged its call has usually ended, and
    /// the engine has let the session go with it.
    ended: Option<StreamStatistics>,
    step: Step,
    asked: bool,
    /// When to hang up a call that is only there to carry audio or a digit.
    listen_until: Option<Instant>,
    /// When to stop waiting for the far end to be worth handing over.
    settled_by: Option<Instant>,
    /// How much audible audio had come back when the resume was agreed, so
    /// `Flow::Dtls` can tell audio after it from audio before the hold.
    audible_at_resume: Option<u32>,
    /// `Flow::Message`'s own send, so its outcome can be told from anybody
    /// else's.
    sent_message: Option<sipral::MessageHandle>,
    /// `Flow::Mwi`'s subscription to `message-summary`.
    subscription: Option<sipral::SubscriptionHandle>,
    /// `Flow::Mwi`'s mailbox `new` count, read from the first notification —
    /// before the voicemail call, whatever it already held from an earlier
    /// run. The flow's claim is that a later notification reads higher than
    /// this, not that it starts at zero.
    mailbox_baseline: Option<u32>,
}

/// Where the script is. One value rather than a pile of flags, because the
/// order matters and a flag can be set twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Registering,
    Placing,
    Talking,
    /// Up, and waiting for the far end to be worth handing over.
    Settling,
    Holding,
    Resuming,
    /// `Flow::HoldCodecChange`, while the call is held: a re-offer naming a
    /// narrower list than the one the call held on.
    ChangingCodecs,
    /// Done with what the flow came to do, and kept up to hear the tone
    /// until `listen_until`; nothing but that timer moves it on.
    Listening,
    /// `Flow::Dtmf4733`: a digit is on its way, or has gone, and this end is
    /// waiting to hear it named back.
    Dialling,
    Consulting,
    Transferring,
    Ending,
    Done,
    /// `Flow::Message`: the MESSAGE is on its way, or has gone, and this end
    /// is waiting for both its own answer and the echo.
    Messaging,
    /// `Flow::Mwi`: subscribed and waiting for a `message-summary` NOTIFY —
    /// the first one, to read the mailbox's count before anything is left in
    /// it, and the one after the voicemail call ends, to see it climb.
    WatchingMailbox,
}

impl Script {
    /// A flow about to start: nothing registered, nothing placed.
    fn new(
        flow: Flow,
        account: AccountId,
        extension: &str,
        other: &str,
        server: &str,
        remote: SocketAddr,
        now: Instant,
    ) -> Self {
        Self {
            flow,
            account,
            extension: extension.to_owned(),
            other: other.to_owned(),
            server: server.to_owned(),
            remote,
            started: now,
            seen: Seen::default(),
            call: None,
            consulted: None,
            original_codec: None,
            ended: None,
            step: Step::Registering,
            asked: false,
            listen_until: None,
            settled_by: None,
            audible_at_resume: None,
            sent_message: None,
            subscription: None,
            mailbox_baseline: None,
        }
    }

    fn on_event(&mut self, endpoint: &mut Endpoint, event: &Event, now: Instant) {
        match event {
            Event::Signalling(signalling) => self.on_signalling(endpoint, signalling, now),
            Event::Media { call, event } => self.on_media(endpoint, *call, event, now),
            // `sipral::Event` is `#[non_exhaustive]`; a variant this harness
            // has never heard of is one it has nothing to judge either
            _ => (),
        }
    }

    fn on_signalling(&mut self, endpoint: &mut Endpoint, event: &UaEvent, now: Instant) {
        match event {
            UaEvent::Registered { .. } => {
                self.seen.saw(Fact::Registered);
                self.advance(endpoint, now);
            }
            UaEvent::Unregistered { .. } => {
                self.seen.saw(Fact::Unregistered);
                self.step = Step::Done;
            }
            UaEvent::RegistrationFailed { reason, status, .. } => {
                self.seen.refused = Some(match status {
                    Some(status) => format!("{reason} ({})", status.get()),
                    None => reason.to_string(),
                });
                self.step = Step::Done;
            }
            UaEvent::CallProgress {
                state: CallState::Ringing | CallState::EarlyMedia,
                ..
            } => self.seen.saw(Fact::Ringing),
            UaEvent::CallConfirmed { call, .. } => {
                if Some(*call) == self.consulted {
                    self.seen.saw(Fact::Consulted);
                } else {
                    self.seen.saw(Fact::Up);
                }
                self.advance(endpoint, now);
            }
            UaEvent::TransferProgress { .. } => self.seen.saw(Fact::Transferring),
            UaEvent::TransferDone { status, .. } => {
                if status.is_success() {
                    self.seen.saw(Fact::Transferred);
                } else {
                    self.seen.refused = Some(format!("the transfer ended {}", status.get()));
                }
                self.advance(endpoint, now);
            }
            UaEvent::DtmfSent { status, .. } => {
                if status.is_success() {
                    self.seen.saw(Fact::DigitSent);
                } else {
                    self.seen.refused = Some(format!("the INFO was answered {}", status.get()));
                }
            }
            // a 491 goes out again by itself; anything else is the far end
            // saying no to a hold, a resume or a codec change, and waiting
            // for the flow's patience to run out would only hide which
            UaEvent::SessionChangeFailed {
                status,
                retry_in: None,
                response,
                ..
            } => {
                self.seen.refused = Some(match status {
                    Some(status) => format!(
                        "the far end refused the session change ({}{})",
                        status.get(),
                        explained(response.as_ref())
                    ),
                    None => "the session change was never answered".to_owned(),
                });
                self.hang_up(endpoint, now);
            }
            UaEvent::SessionChanged { hold, .. } => {
                if hold.local {
                    self.seen.saw(Fact::Held);
                } else if self.seen.has(Fact::Held) {
                    self.seen.saw(Fact::Resumed);
                    if self.audible_at_resume.is_none() {
                        self.audible_at_resume = Some(self.heard(endpoint).audible);
                    }
                }
                self.advance(endpoint, now);
            }
            UaEvent::CallEnded {
                reason,
                status,
                response,
                ..
            } => {
                self.seen.saw(Fact::Over);
                if !self.seen.has(Fact::Up) {
                    self.seen.refused = Some(match status {
                        // a refusal usually says why in the reason phrase or a
                        // Warning, and the number alone sends you guessing
                        Some(status) => {
                            format!(
                                "{reason} ({}{})",
                                status.get(),
                                explained(response.as_ref())
                            )
                        }
                        None => reason.to_string(),
                    });
                }
                self.finish_or_watch_mailbox(endpoint, now);
            }
            other => self.on_message_or_mwi(endpoint, other, now),
        }
    }

    /// `Flow::Message` and `Flow::Mwi`'s own events. Factored out of
    /// `on_signalling` for the reason `send_dtmf_by_info` is factored out of
    /// `advance`, and matched here rather than guarded in the caller's own
    /// `match` for the same reason.
    fn on_message_or_mwi(&mut self, endpoint: &mut Endpoint, event: &UaEvent, now: Instant) {
        match event {
            UaEvent::MessageSent {
                message, status, ..
            } if self.flow == Flow::Message && Some(*message) == self.sent_message => {
                if status.is_success() || status.get() == 202 {
                    self.seen.saw(Fact::MessageAccepted);
                } else {
                    self.seen.refused = Some(format!("the MESSAGE was answered {}", status.get()));
                    self.step = Step::Ending;
                }
                self.finish_message_flow(endpoint, now);
            }
            UaEvent::MessageReceived { .. } if self.flow == Flow::Message => {
                self.seen.saw(Fact::MessageEchoed);
                self.finish_message_flow(endpoint, now);
            }
            UaEvent::Subscribed { subscription, .. }
                if self.flow == Flow::Mwi && Some(*subscription) == self.subscription =>
            {
                self.seen.saw(Fact::Subscribed);
            }
            UaEvent::SubscriptionEnded { reason, .. }
                if self.flow == Flow::Mwi
                    && self.subscription.is_some()
                    && !self.seen.has(Fact::MailboxCounted) =>
            {
                self.seen.refused = Some(format!("the subscription ended: {reason}"));
                self.step = Step::Ending;
            }
            UaEvent::MessagesWaiting {
                subscription, new, ..
            } if self.flow == Flow::Mwi && Some(*subscription) == self.subscription => {
                self.on_mailbox_count(endpoint, *new, now);
            }
            _ => (),
        }
    }

    /// `Flow::Mwi`'s own `UaEvent::CallEnded`: the voicemail call ending is
    /// not the flow ending, since the claim is about the mailbox count
    /// after it (`Fact::MailboxCounted`). Every other flow finishes as soon
    /// as its call ends.
    fn finish_or_watch_mailbox(&mut self, endpoint: &mut Endpoint, now: Instant) {
        if self.flow == Flow::Mwi
            && self.seen.refused.is_none()
            && !self.seen.has(Fact::MailboxCounted)
        {
            self.step = Step::WatchingMailbox;
        } else {
            self.finish(endpoint, now);
        }
    }

    /// `Flow::Mwi`'s own reaction to a `message-summary` notification: the
    /// first one is the baseline, read before anything is left in the
    /// mailbox, and the primary call goes out right after it; a later one
    /// that reads higher is the flow's claim proved.
    fn on_mailbox_count(&mut self, endpoint: &mut Endpoint, new: u32, now: Instant) {
        match self.mailbox_baseline {
            None => {
                self.mailbox_baseline = Some(new);
                self.place_primary_call(endpoint, now);
            }
            Some(baseline) if new > baseline => {
                self.seen.saw(Fact::MailboxCounted);
                self.finish(endpoint, now);
            }
            Some(_) => (),
        }
    }

    /// `Flow::Message` is over once its own send has been answered and the
    /// echo has arrived; either may come first.
    fn finish_message_flow(&mut self, endpoint: &mut Endpoint, now: Instant) {
        if self.step != Step::Ending
            && self.seen.has(Fact::MessageAccepted)
            && self.seen.has(Fact::MessageEchoed)
        {
            self.finish(endpoint, now);
        }
    }

    fn on_media(
        &mut self,
        endpoint: &mut Endpoint,
        call: CallHandle,
        event: &MediaEvent,
        now: Instant,
    ) {
        match *event {
            MediaEvent::Started { codec, .. } if Some(call) == self.call => {
                self.original_codec.get_or_insert(codec);
                if matches!(self.flow, Flow::Srtp | Flow::PeerSrtp)
                    && endpoint
                        .engine
                        .session(call)
                        .is_some_and(|session| session.is_encrypted())
                {
                    self.seen.saw(Fact::Encrypted);
                }
            }
            MediaEvent::Changed { codec, .. }
                if Some(call) == self.call
                    && self.flow == Flow::HoldCodecChange
                    && self.seen.has(Fact::Held) =>
            {
                // the change asked for while the call was held, and then the
                // resume after it. Only once the hold was agreed: a codec that
                // moved before it is not the change this flow asked for. And
                // a resume that went back to the codec the call held on is
                // the change undone, which the far end's own answer to it is
                // the one place to see
                if self.original_codec.is_some_and(|was| was != codec) {
                    self.seen.saw(Fact::CodecChanged);
                } else if self.seen.has(Fact::CodecChanged) {
                    self.seen.refused =
                        Some(format!("the resume went back to {}", codec.encoding_name()));
                }
            }
            // the handshake finished and its keys are in: the one event that
            // says a DTLS-SRTP call is encrypted, since at `Started` it is
            // still waiting for them
            MediaEvent::Secured { .. }
                if Some(call) == self.call && matches!(self.flow, Flow::Dtls | Flow::PeerDtls) =>
            {
                self.seen.saw(Fact::Encrypted);
            }
            // a handshake that gave up, a role or a certificate the far end
            // moved: this flow's whole claim, and nothing to wait out
            MediaEvent::Failed(ref error)
                if Some(call) == self.call && matches!(self.flow, Flow::Dtls | Flow::PeerDtls) =>
            {
                self.seen.refused = Some(format!("media: {error}"));
                self.hang_up(endpoint, now);
            }
            MediaEvent::DigitReceived { digit, .. }
                if Some(call) == self.call && digit == Some(TEST_DIGIT.as_char()) =>
            {
                self.seen.saw(Fact::DigitConfirmed);
                self.hang_up(endpoint, now);
            }
            MediaEvent::Ended(statistics) if Some(call) == self.call => {
                self.ended = Some(statistics);
            }
            _ => (),
        }
    }

    fn on_tick(&mut self, endpoint: &mut Endpoint, now: Instant) {
        // once, not once per tick inside some window: the loop turns as fast
        // as the socket lets it, and a window let a single flow open a dozen
        // REGISTER transactions before the first answer came back
        if !self.asked {
            self.asked = true;
            let asked = endpoint.agent.register(self.account, now);
            self.tried("register", asked);
        }
        if self.listen_until.is_some_and(|due| now >= due) {
            self.listen_until = None;
            self.hang_up(endpoint, now);
        }
        // audio coming back is the far end saying it has bridged the call to
        // something, which is what makes it transferable
        if let Some(due) = self.settled_by
            && (self.heard(endpoint).received > 0 || now >= due)
        {
            self.settled_by = None;
            self.advance(endpoint, now);
        }
        if self.step == Step::Done || now > self.started + patience() {
            self.step = Step::Done;
        }
    }

    /// The next thing this flow does, once the last one has happened.
    fn advance(&mut self, endpoint: &mut Endpoint, now: Instant) {
        if matches!(self.flow, Flow::Dtls | Flow::PeerDtls)
            && self.advance_keyed_hold(endpoint, now)
        {
            return;
        }
        match self.step {
            Step::Registering if self.flow == Flow::Register => {
                self.step = Step::Done;
                let _ = endpoint.agent.unregister(self.account, now);
                self.step = Step::Ending;
            }
            Step::Registering if self.flow == Flow::Message => self.start_message(endpoint, now),
            Step::Registering if self.flow == Flow::Mwi => {
                self.start_watching_mailbox(endpoint, now);
            }
            Step::Registering => self.place_primary_call(endpoint, now),
            Step::Talking if self.flow == Flow::Hold || self.flow == Flow::HoldCodecChange => {
                self.step = Step::Holding;
                if let Some(call) = self.call {
                    let asked = endpoint.agent.hold(call, now);
                    self.tried("hold", asked);
                }
            }
            Step::Holding if matches!(self.flow, Flow::Hold | Flow::Dtls | Flow::PeerDtls) => {
                self.step = Step::Resuming;
                if let Some(call) = self.call {
                    let asked = endpoint.agent.resume(call, now);
                    self.tried("resume", asked);
                }
            }
            Step::Holding => self.change_codecs_while_held(endpoint, now),
            Step::ChangingCodecs => {
                self.step = Step::Resuming;
                if let Some(call) = self.call {
                    let asked = endpoint.agent.resume(call, now);
                    self.tried("resume", asked);
                }
            }
            // not straight into the REFER: see SETTLE. The attended flow needs
            // no such wait, because placing the second leg is itself the delay
            Step::Talking if self.flow == Flow::Blind => {
                self.step = Step::Settling;
                self.settled_by = Some(now + SETTLE);
            }
            Step::Settling => {
                self.step = Step::Transferring;
                if let (Some(call), Some(target)) = (self.call, self.target()) {
                    let asked = endpoint.agent.transfer(call, &target, now);
                    self.tried("transfer", asked);
                }
            }
            Step::Talking if self.flow == Flow::Attended => {
                self.step = Step::Consulting;
                let other = self.other.clone();
                let media = CallMedia::new(catalog(), MediaConfig::default());
                match self.place_at(endpoint, &other, media, now) {
                    Ok(second) => self.consulted = Some(second),
                    Err(error) => {
                        self.seen.refused = Some(format!("consult: {error}"));
                        self.step = Step::Done;
                    }
                }
            }
            // the second leg is up, so there is somebody to hand the call to
            Step::Consulting => {
                self.step = Step::Transferring;
                if let (Some(call), Some(other)) = (self.call, self.consulted) {
                    let asked = endpoint.agent.transfer_to(call, other, now);
                    self.tried("attended transfer", asked);
                }
            }
            // a plain call is the one that carries the tone, so it waits.
            // `Flow::Mwi`'s mailbox leg is the same shape: dwell, then hang
            // up, which is what makes 9007 announce the message. `PeerSrtp`
            // is `Flow::Srtp` again, against the phone-to-phone peer instead
            // of a server
            Step::Talking
                if matches!(
                    self.flow,
                    Flow::Call | Flow::Srtp | Flow::Mwi | Flow::PeerSrtp | Flow::G729
                ) =>
            {
                self.listen_until = Some(now + dwell());
            }
            Step::Talking if self.flow == Flow::Dtmf4733 => {
                self.step = Step::Dialling;
                let dialled = self
                    .call
                    .and_then(|call| endpoint.engine.session(call))
                    .map(|mut session| session.dial(&TEST_DIGIT.to_string(), DEFAULT_DIGIT));
                if let Some(Err(error)) = dialled {
                    self.seen.refused = Some(format!("dial: {error}"));
                    self.step = Step::Ending;
                }
                // whichever answers first: the digit named back, or the timer
                self.listen_until = Some(now + dwell() + Duration::from_secs(2));
            }
            Step::Talking if self.flow == Flow::DtmfInfo => self.send_dtmf_by_info(endpoint, now),
            Step::Talking | Step::Resuming | Step::Dialling | Step::Transferring => {
                self.hang_up(endpoint, now);
            }
            Step::Placing
            | Step::Listening
            | Step::Ending
            | Step::Done
            | Step::Messaging
            | Step::WatchingMailbox => (),
        }
    }

    /// `Flow::Dtls`'s own steps, the ones no other flow takes; `true` when
    /// this was one of them. Keyed and heard before anything is re-offered,
    /// so that the audio after the resume is measured against a call that had
    /// some, and kept up after the resume to hear it. Factored out of
    /// `advance` for the reason `send_dtmf_by_info` gives.
    fn advance_keyed_hold(&mut self, endpoint: &mut Endpoint, now: Instant) -> bool {
        match self.step {
            Step::Talking => {
                self.step = Step::Settling;
                self.settled_by = Some(now + dwell());
            }
            Step::Settling => {
                self.step = Step::Holding;
                if let Some(call) = self.call {
                    let asked = endpoint.agent.hold(call, now);
                    self.tried("hold", asked);
                }
            }
            Step::Resuming => {
                self.step = Step::Listening;
                self.listen_until = Some(now + dwell());
            }
            _ => return false,
        }
        true
    }

    /// `Flow::HoldCodecChange`'s own `Step::Holding`: a narrower list than
    /// the call held on, offered while it is still held — which the change
    /// keeps. Factored out of `advance` for the reason `send_dtmf_by_info`
    /// gives.
    fn change_codecs_while_held(&mut self, endpoint: &mut Endpoint, now: Instant) {
        self.step = Step::ChangingCodecs;
        if let Some(call) = self.call {
            let asked = endpoint
                .engine
                .change_codecs(&mut endpoint.agent, call, &["PCMA"], now);
            self.tried("codec change", asked);
        }
    }

    /// `Flow::DtmfInfo`'s own `Step::Talking`: send the test digit by INFO
    /// instead of `Flow::Dtmf4733`'s media, and wait for it to be named back
    /// the same way that flow does. Factored out of `advance` so that arm
    /// does not push it past `clippy::too_many_lines`.
    fn send_dtmf_by_info(&mut self, endpoint: &mut Endpoint, now: Instant) {
        self.step = Step::Dialling;
        if let Some(call) = self.call {
            let asked = endpoint.agent.send_dtmf_info(
                call,
                &TEST_DIGIT.to_string(),
                DtmfInfoForm::Relay,
                0,
                now,
            );
            self.tried("send dtmf by info", asked);
        }
        // whichever answers first: the digit named back, or the timer
        self.listen_until = Some(now + dwell() + Duration::from_secs(2));
    }

    /// Every flow but `Flow::Register`, `Flow::Message` and `Flow::Mwi`'s own
    /// `Step::Registering`: place the primary, media-carrying call. Factored
    /// out of `advance` for the reason `send_dtmf_by_info` gives.
    fn place_primary_call(&mut self, endpoint: &mut Endpoint, now: Instant) {
        self.step = Step::Placing;
        let media = CallMedia::new(catalog_for(self.flow), MediaConfig::default());
        let extension = self.call_extension();
        match self.place_at(endpoint, &extension, media, now) {
            Ok(call) => self.call = Some(call),
            Err(error) => {
                self.seen.refused = Some(format!("call: {error}"));
                self.step = Step::Ending;
            }
        }
        self.step = Step::Talking;
    }

    /// `Flow::Message`'s own `Step::Registering`: send the MESSAGE. Factored
    /// out of `advance` for the reason `send_dtmf_by_info` gives.
    fn start_message(&mut self, endpoint: &mut Endpoint, now: Instant) {
        self.step = Step::Messaging;
        let Ok(target) = Uri::parse_str(&format!("sip:9006@{}", self.server)) else {
            self.seen.refused = Some("9006 is not a URI on this server".to_owned());
            self.step = Step::Ending;
            return;
        };
        match endpoint.agent.message(
            self.account,
            target,
            b"text/plain",
            MESSAGE_BODY.as_bytes(),
            now,
        ) {
            Ok(handle) => self.sent_message = Some(handle),
            Err(error) => {
                self.seen.refused = Some(format!("message: {error}"));
                self.step = Step::Ending;
            }
        }
    }

    /// `Flow::Mwi`'s own `Step::Registering`: subscribe to this account's own
    /// mailbox. Factored out of `advance` for the reason `send_dtmf_by_info`
    /// gives.
    fn start_watching_mailbox(&mut self, endpoint: &mut Endpoint, now: Instant) {
        self.step = Step::WatchingMailbox;
        let Some(target) = endpoint
            .agent
            .account(self.account)
            .map(|account| account.aor().clone())
        else {
            self.seen.refused = Some("no account to subscribe from".to_owned());
            self.step = Step::Ending;
            return;
        };
        let wanted = Subscribe::new(target, "message-summary");
        match endpoint.agent.subscribe(self.account, &wanted, now) {
            Ok(handle) => self.subscription = Some(handle),
            Err(error) => {
                self.seen.refused = Some(format!("subscribe: {error}"));
                self.step = Step::Ending;
            }
        }
    }

    /// Ask the stack for something, and remember it if it says no.
    ///
    /// Swallowing these is how a flow ends up reporting that the far end never
    /// answered, when the truth is that nothing was ever sent.
    fn tried<E: core::fmt::Display>(&mut self, what: &str, outcome: Result<(), E>) {
        if let Err(error) = outcome {
            self.seen.refused = Some(format!("{what}: {error}"));
            self.step = Step::Ending;
        }
    }

    /// Who a transfer hands the call to.
    fn target(&self) -> Option<Uri> {
        Uri::parse_str(&format!("sip:{}@{}", self.other, self.server)).ok()
    }

    /// The extension this flow's primary call dials — `self.extension`
    /// (9000 unless told otherwise) for every flow except the ones that need
    /// a dialplan entry of their own: `Flow::Dtmf4733` and `Flow::DtmfInfo`
    /// (interop/asterisk and interop/freeswitch both add 9003 for the first;
    /// only Asterisk runs the second, over its own `labuser-infodtmf`
    /// endpoint), `Flow::Srtp` (9004), `Flow::Mwi`'s own voicemail
    /// extension (9007) and `Flow::G729`'s echo (9008), all Asterisk only — see
    /// `interop/asterisk/extensions.conf` — and `Flow::Dtls` (9005, on both).
    /// `Flow::Message` places no call at all; its own extension (9006) is
    /// named directly in `advance`. `Flow::Call` and `Flow::Hold` reused
    /// against the phone-to-phone peer are `self.extension` too —
    /// scripts/lab.sh passes baresip's own AOR name for that step rather
    /// than 9000 — but that peer's own SRTP and DTLS-SRTP accounts are
    /// fixed names for the same reason 9004 and 9005 are: one AOR per media
    /// policy (interop/baresip/config/accounts), not one per extension
    /// number, since baresip is a single client rather than a dialplan.
    fn call_extension(&self) -> String {
        match self.flow {
            Flow::Dtmf4733 | Flow::DtmfInfo => "9003".to_owned(),
            Flow::Srtp => "9004".to_owned(),
            Flow::Dtls => "9005".to_owned(),
            Flow::Mwi => "9007".to_owned(),
            Flow::G729 => "9008".to_owned(),
            Flow::PeerSrtp => "baresip-srtp".to_owned(),
            Flow::PeerDtls => "baresip-dtls".to_owned(),
            _ => self.extension.clone(),
        }
    }

    /// Place a call to `extension` on this flow's own server and account,
    /// with `media`'s catalogue — the primary leg and an attended transfer's
    /// consultation leg are both exactly this, so the two arms in
    /// [`Script::advance`] that place one share it.
    fn place_at(
        &self,
        endpoint: &mut Endpoint,
        extension: &str,
        media: CallMedia,
        now: Instant,
    ) -> Result<CallHandle, String> {
        let target = uri(&format!("sip:{extension}@{}", self.server))?;
        let placing = OutgoingCall::new(target).to_address(endpoint.transport, self.remote);
        place_call(endpoint, self.account, placing, media, self.remote, now)
    }

    /// The primary call's own `Quality`, for the result line: what the call
    /// ended on, or what it is doing now if it is still up.
    fn quality(&self, endpoint: &mut Endpoint, now: Instant) -> Option<Quality> {
        if let Some(ended) = self.ended {
            return Some(ended.quality);
        }
        self.call
            .and_then(|call| endpoint.engine.session(call))
            .map(|session| session.statistics(now).quality)
    }

    /// The primary call's RFC 3611 VoIP Metrics, the same way
    /// [`Script::quality`] reads its `Quality`: what the call ended with, or
    /// what it has measured so far if it is still up. `None` until this
    /// stream has identified a source to report on.
    fn voip_metrics(&self, endpoint: &mut Endpoint, now: Instant) -> Option<VoipMetricsBlock> {
        if let Some(ended) = self.ended {
            return ended.voip_metrics;
        }
        self.call
            .and_then(|call| endpoint.engine.session(call))
            .and_then(|session| session.statistics(now).voip_metrics)
    }

    fn heard(&self, endpoint: &Endpoint) -> audio::Heard {
        self.call
            .and_then(|call| endpoint.media.get(&call))
            .map(Media::heard)
            .unwrap_or_default()
    }

    /// What the audio quality gate measured on the primary call, when
    /// `SIPRAL_AUDIO_GATE` asked for one — `None` on a flow it was never
    /// engaged for, exactly as `Media::quality_report` is.
    fn quality_report(&self, endpoint: &Endpoint) -> Option<quality::Report> {
        self.call
            .and_then(|call| endpoint.media.get(&call))
            .and_then(Media::quality_report)
    }

    fn hang_up(&mut self, endpoint: &mut Endpoint, now: Instant) {
        if self.step == Step::Ending || self.step == Step::Done {
            return;
        }
        self.step = Step::Ending;
        if let Some(call) = self.call {
            self.seen.saw(Fact::Ours);
            let _ = endpoint.agent.hangup(call, now);
        }
    }

    fn finish(&mut self, endpoint: &mut Endpoint, now: Instant) {
        if let Some(subscription) = self.subscription.take() {
            let _ = endpoint.agent.unsubscribe(subscription, now);
        }
        let _ = endpoint.agent.unregister(self.account, now);
        self.step = Step::Done;
    }

    /// What this flow said it would prove.
    ///
    /// `heard` is this flow's own tally of its primary call's audio, and
    /// `require_audio` is whether `SIPRAL_REQUIRE_AUDIO` asked for any of it
    /// to have come back. The caller reads the environment, so the judgement
    /// itself does not.
    fn verdict(&self, heard: audio::Heard, require_audio: bool) -> Result<(), String> {
        if let Some(ref why) = self.seen.refused {
            return Err(why.clone());
        }
        for (fact, why) in self.owed() {
            if !self.seen.has(*fact) {
                return Err((*why).to_owned());
            }
        }
        if matches!(self.flow, Flow::Srtp | Flow::PeerSrtp) && !self.seen.has(Fact::Encrypted) {
            return Err("the call connected but never ran under SDES".to_owned());
        }
        // Audio is asked for only when something is known to send it back, and
        // only of the calls that dwell on the tone: the others hang up as soon
        // as what they came to prove has happened. The SRTP call dwells on the
        // same tone, and a stream that agreed a key and never decrypted a frame
        // is the failure that flow exists to find.
        if matches!(self.flow, Flow::Call | Flow::Srtp | Flow::PeerSrtp)
            && require_audio
            && heard.audible == 0
        {
            return Err(format!(
                "nothing audible came back: {} sent, {} received, {} refused",
                heard.sent, heard.received, heard.refused
            ));
        }
        // the G.729 call's claim is the codec and the echo together: a call
        // that settled on anything else proved nothing about G.729, and the
        // echo of a tone that went out as G.729 has to come back as more
        // than a stray frame — half a second of it, of the two seconds the
        // call dwells, a third of which is the tone's own pauses
        if self.flow == Flow::G729 {
            if let Some(codec) = self.original_codec.filter(|codec| *codec != Codec::G729) {
                return Err(format!("the call settled on {codec}, not G.729"));
            }
            if require_audio && heard.audible < G729_ECHOED {
                return Err(format!(
                    "the echo came back as {} audible frames of {G729_ECHOED} wanted: {} sent, \
                     {} received, {} refused",
                    heard.audible, heard.sent, heard.received, heard.refused
                ));
            }
        }
        // and the DTLS call's claim is about after the re-offers, not before:
        // audio before the hold only says the first handshake worked
        if matches!(self.flow, Flow::Dtls | Flow::PeerDtls)
            && require_audio
            && heard.audible <= self.audible_at_resume.unwrap_or(heard.audible)
        {
            return Err(format!(
                "nothing audible came back after the resume: {} audible in all, {} sent, \
                 {} received, {} refused",
                heard.audible, heard.sent, heard.received, heard.refused
            ));
        }
        Ok(())
    }

    /// Every fact this flow has to have seen, each with the sentence that
    /// says which one it did not.
    const fn owed(&self) -> &'static [(Fact, &'static str)] {
        match self.flow {
            Flow::Register => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Unregistered, "the binding was not given back"),
            ],
            // Ours, and before Over: a far end that answers and hangs up half a
            // millisecond later satisfies "connected" and "ended" without the
            // call ever having been one
            Flow::Call | Flow::Srtp | Flow::PeerSrtp | Flow::G729 => {
                const CALL: &[(Fact, &str)] = &[
                    (Fact::Registered, "no binding was granted"),
                    (Fact::Up, "the call did not connect"),
                    (Fact::Ours, "the far end ended the call before we asked"),
                    (Fact::Over, "the call did not end"),
                ];
                CALL
            }
            Flow::Hold => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Held, "the hold was not agreed"),
                (Fact::Resumed, "the resume was not agreed"),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
            // No Ours: a transfer that worked is a call this end is not in
            // any more, and the far end is right to hang it up. And no
            // Transferring either — RFC 3515 §2.4.4 asks for a 100 Trying
            // first only when there is something to wait for, and FreeSWITCH
            // sends one NOTIFY, terminated, carrying the final status
            Flow::Blind => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Transferred, "the transfer did not complete"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::Attended => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Consulted, "the consultation call did not connect"),
                (Fact::Transferred, "the transfer did not complete"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::Dtmf4733 => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (
                    Fact::DigitConfirmed,
                    "the digit sent never came back named the same way",
                ),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::DtmfInfo => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::DigitSent, "the INFO was never answered with success"),
                (
                    Fact::DigitConfirmed,
                    "the digit sent by INFO never came back named the same way",
                ),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::HoldCodecChange => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (Fact::Held, "the hold was not agreed"),
                (Fact::Resumed, "the resume was not agreed"),
                (
                    Fact::CodecChanged,
                    "the codec change never moved the call off the one it held on",
                ),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::Dtls | Flow::PeerDtls => &[
                (Fact::Registered, "no binding was granted"),
                (Fact::Up, "the call did not connect"),
                (
                    Fact::Encrypted,
                    "the call connected but its DTLS-SRTP handshake never keyed it",
                ),
                (Fact::Held, "the hold was not agreed"),
                (Fact::Resumed, "the resume was not agreed"),
                (Fact::Ours, "the far end ended the call before we asked"),
                (Fact::Over, "the call did not end"),
            ],
            Flow::Message => owed_message(),
            Flow::Mwi => owed_mwi(),
        }
    }
}

/// `Flow::Message`'s own [`Script::owed`]. Factored out for the same reason
/// `owed`'s other long arms are not: `clippy::too_many_lines` counts the
/// whole function, not one `match` arm.
const fn owed_message() -> &'static [(Fact, &'static str)] {
    &[
        (Fact::Registered, "no binding was granted"),
        (
            Fact::MessageAccepted,
            "the MESSAGE was never answered with success",
        ),
        (Fact::MessageEchoed, "no MESSAGE came back"),
    ]
}

/// `Flow::Mwi`'s own [`Script::owed`].
const fn owed_mwi() -> &'static [(Fact, &'static str)] {
    &[
        (Fact::Registered, "no binding was granted"),
        (
            Fact::Subscribed,
            "the message-summary subscription was never granted",
        ),
        (Fact::Up, "the voicemail call did not connect"),
        (Fact::Ours, "the far end ended the call before we asked"),
        (Fact::Over, "the call did not end"),
        (
            Fact::MailboxCounted,
            "the mailbox's new-message count never went up after the voicemail was left",
        ),
    ]
}

/// Place a call with `media`'s catalogue, opening this call's own RTP socket
/// first so its port can go in the offer.
///
/// Shared between `main`'s flow script, which places both legs of an
/// attended transfer this way, and `pair`'s caller.
pub(crate) fn place_call(
    endpoint: &mut Endpoint,
    account: AccountId,
    outgoing: OutgoingCall,
    media: CallMedia,
    remote: SocketAddr,
    now: Instant,
) -> Result<CallHandle, String> {
    // a call handle is only minted by `place_with`, and the socket has to
    // exist before that call, so it is opened against a handle nothing has
    // been placed on yet and moved once the real one is known
    let placeholder = Media::bind(now)?;
    let port = placeholder.port()?;
    let local = SocketAddr::new(route_to(remote), port);
    let call = endpoint
        .engine
        .place_with(&mut endpoint.agent, account, outgoing, local, media, now)
        .map_err(|error| error.to_string())?;
    endpoint.media.insert(call, placeholder);
    Ok(call)
}

/// The address that reaches the lab, not a wildcard. What this is given is
/// what goes into every `Via`, and RFC 3261 §18.1.1 makes sent-by the place
/// a response is sent to; `0.0.0.0` names no such place. Asterisk forgave
/// it because it answers to `rport`, and that is exactly why it went
/// unnoticed — a carrier that reads the Via instead will not.
fn run(
    flow: Flow,
    server: &str,
    remote: SocketAddr,
    extension: &str,
    other: &str,
    user: &str,
    pass: &str,
) -> Result<String, String> {
    let bind_addr = SocketAddr::new(route_to(remote), 0);
    let now = Instant::now();
    let mut endpoint = Endpoint::bind(seed(flow), media_seed(flow), bind_addr, catalog(), now)?;
    let account = endpoint.account(user, pass, server, remote)?;

    let mut script = Script::new(flow, account, extension, other, server, remote, now);

    drive(&mut endpoint, &mut script, now + patience());
    let heard = script.heard(&endpoint);
    script.verdict(heard, env::var("SIPRAL_REQUIRE_AUDIO").is_ok())?;
    // the audio quality gate, when `SIPRAL_AUDIO_GATE` engaged one on the
    // primary call's media: a call that connected, dwelled and ended can
    // still be a failure the ordinary facts above never see, if what it
    // carried clicked at a concealment splice or measured too noisy to
    // trust. See `quality`'s own module doc.
    let quality = script.quality_report(&endpoint);
    if let Some(report) = quality
        && let Err(why) = report.verdict()
    {
        return Err(format!("{why} ({})", report.summary()));
    }

    if heard.sent == 0 {
        return Ok(String::new());
    }
    let mut said = format!(
        "   ({} sent, {} back, {} audible, {} refused",
        heard.sent, heard.received, heard.audible, heard.refused
    );
    // G.729's Annex B, where the call used it: SID frames out and back, and
    // the pauses played as the codec's comfort noise
    if heard.sid_sent > 0 || heard.sid_received > 0 {
        use std::fmt::Write as _;
        let _ = write!(
            said,
            "; SID {} sent, {} back, {} frames of comfort noise",
            heard.sid_sent, heard.sid_received, heard.comfort
        );
    }
    if let Some(report) = quality {
        use std::fmt::Write as _;
        let _ = write!(said, "; {}", report.summary());
    }
    // the session's own account of the path, which is the only thing that
    // says anything under an impaired network: how much never arrived, how
    // late the rest was, and how much had to be invented
    if let Some(quality) = script.quality(&mut endpoint, Instant::now()) {
        use std::fmt::Write as _;
        let _ = write!(
            said,
            "; lost {}, late {}, jitter {}ms, delay {}ms of {}ms, \
             shrunk {}, stretched {}",
            quality.lost,
            quality.discarded_late,
            quality.jitter.as_millis(),
            quality.delay.as_millis(),
            quality.target_delay.as_millis(),
            quality.shrunk,
            quality.stretched
        );
    }
    // RFC 3611's own read on the call, from the same stream — the R factor
    // and the two mean opinion scores a simplified E-model rates it at, or
    // "n/a" for a codec G.113 tabulates no Ie/Bpl for (SS4.7.5's own
    // sentinel, never a guess).
    if let Some(block) = script.voip_metrics(&mut endpoint, Instant::now()) {
        use std::fmt::Write as _;
        let mos = |value: u8| {
            if value == UNAVAILABLE {
                "n/a".to_string()
            } else {
                format!("{}.{}", value / 10, value % 10)
            }
        };
        let r_factor = if block.r_factor == UNAVAILABLE {
            "n/a".to_string()
        } else {
            block.r_factor.to_string()
        };
        let _ = write!(
            said,
            "; R {r_factor}, MOS-LQ {}, MOS-CQ {}",
            mos(block.mos_lq),
            mos(block.mos_cq)
        );
    }
    said.push(')');
    Ok(said)
}

/// The address to put in `Contact`, which is the one the far end can reach.
///
/// Binding to a wildcard gives back `0.0.0.0`, and a registrar told to send
/// calls there will send them nowhere. The address that reaches the lab is the
/// one on the route to it.
pub(crate) fn advertised(local: SocketAddr, remote: SocketAddr) -> SocketAddr {
    if local.ip().is_unspecified() {
        return SocketAddr::new(route_to(remote), local.port());
    }
    local
}

/// Which of this host's addresses a datagram to `remote` would leave from.
pub(crate) fn route_to(remote: SocketAddr) -> std::net::IpAddr {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect(remote)?;
            socket.local_addr()
        })
        .map_or(std::net::IpAddr::from([127, 0, 0, 1]), |address| {
            address.ip()
        })
}

/// What a refusal said about itself, beyond its number.
fn explained(response: Option<&OwnedMessage>) -> String {
    let Some(response) = response else {
        return String::new();
    };
    let raw = response.as_raw();
    let mut said = String::new();
    if let Some(reason) = raw.reason() {
        said.push(' ');
        said.push_str(&String::from_utf8_lossy(reason));
    }
    if let Some(warning) = HeaderName::from_bytes(b"Warning").and_then(|name| raw.header(name)) {
        said.push_str(" — ");
        said.push_str(&String::from_utf8_lossy(warning));
    }
    said
}

fn resolve(host: &str, port: u16) -> Option<SocketAddr> {
    std::net::ToSocketAddrs::to_socket_addrs(&(host, port))
        .ok()?
        .next()
}

pub(crate) fn uri(text: &str) -> Result<Uri, String> {
    Uri::parse_str(text).map_err(|_| format!("{text} is not a URI"))
}

/// A different signalling seed per flow, so that two runs never mint the same
/// branch.
const fn seed(flow: Flow) -> [u8; 32] {
    match flow {
        Flow::Register => [17; 32],
        Flow::Call => [29; 32],
        Flow::Hold => [41; 32],
        Flow::Blind => [53; 32],
        Flow::Attended => [67; 32],
        Flow::Dtmf4733 => [79; 32],
        Flow::DtmfInfo => [97; 32],
        Flow::Srtp => [83; 32],
        Flow::HoldCodecChange => [89; 32],
        Flow::Dtls => [101; 32],
        Flow::Message => [109; 32],
        Flow::Mwi => [113; 32],
        Flow::PeerSrtp => [131; 32],
        Flow::PeerDtls => [137; 32],
        Flow::G729 => [139; 32],
    }
}

/// A media seed independent of the signalling one — `MediaEngine::new`'s own
/// requirement, so that a recording of this run's signalling never carries
/// the means to derive whatever key an SRTP flow drew.
const fn media_seed(flow: Flow) -> [u8; 32] {
    match flow {
        Flow::Register => [117; 32],
        Flow::Call => [129; 32],
        Flow::Hold => [141; 32],
        Flow::Blind => [153; 32],
        Flow::Attended => [167; 32],
        Flow::Dtmf4733 => [179; 32],
        Flow::DtmfInfo => [197; 32],
        Flow::Srtp => [183; 32],
        Flow::HoldCodecChange => [189; 32],
        Flow::Dtls => [201; 32],
        Flow::Message => [211; 32],
        Flow::Mwi => [223; 32],
        Flow::PeerSrtp => [227; 32],
        Flow::PeerDtls => [229; 32],
        Flow::G729 => [233; 32],
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
    use std::time::{Duration, Instant};

    use sipral::{CallMedia, Codec, Direction, Event, MediaConfig, MediaEvent, OutgoingCall};

    use super::{Endpoint, Fact, Flow, Script, Step, catalog, drive, media_seed, place_call, seed};
    use crate::audio::Heard;

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// A registrar that grants every binding and a far end that answers every
    /// INVITE busy, on one loopback socket, until `until`. Returns every
    /// request it was sent, in the order they came.
    fn busy_registrar(socket: &UdpSocket, until: Instant) -> Vec<String> {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("a read timeout");
        let mut seen = Vec::new();
        let mut inbox = vec![0_u8; 65_535];
        while Instant::now() < until {
            let Ok((length, from)) = socket.recv_from(&mut inbox) else {
                continue;
            };
            let request = String::from_utf8_lossy(&inbox[..length]).into_owned();
            let method = request.split(' ').next().unwrap_or_default().to_owned();
            let status = match method.as_str() {
                "REGISTER" => "200 OK",
                "INVITE" => "486 Busy Here",
                _ => {
                    seen.push(request);
                    continue;
                }
            };
            let mut response = format!("SIP/2.0 {status}\r\n");
            for header in request.lines() {
                let name = header
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .trim()
                    .to_ascii_lowercase();
                match name.as_str() {
                    "via" | "from" | "call-id" | "cseq" => {
                        response.push_str(header);
                        response.push_str("\r\n");
                    }
                    "to" => {
                        response.push_str(header);
                        response.push_str(";tag=lab\r\n");
                    }
                    "contact" if method == "REGISTER" => {
                        let uri = header
                            .split_once('<')
                            .and_then(|(_, rest)| rest.split_once('>'))
                            .map(|(uri, _)| uri)
                            .unwrap_or_default();
                        response.push_str("Contact: <");
                        response.push_str(uri);
                        response.push_str(">;expires=300\r\n");
                    }
                    _ => {}
                }
            }
            if method == "REGISTER" {
                response.push_str("Expires: 300\r\n");
            }
            response.push_str("Content-Length: 0\r\n\r\n");
            let _ = socket.send_to(response.as_bytes(), from);
            seen.push(request);
        }
        seen
    }

    /// `Flow::HoldCodecChange` counts a codec change only once the hold was
    /// agreed. A session that moved codec before any hold — a far end that
    /// re-offered on its own — is not the change this flow asked for, and
    /// counting it lets the flow pass on something that happened before the
    /// hold did. And a resume that lands back on the codec the call held on
    /// is the change undone, not a second one.
    #[test]
    fn a_codec_that_moves_before_the_hold_is_not_the_change_this_flow_asked_for() {
        let far_end = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).expect("a far end");
        let remote = far_end.local_addr().expect("bound");
        let (mut endpoint, mut script) = scripted(Flow::HoldCodecChange, remote);
        let target = super::uri("sip:9000@127.0.0.1").expect("a URI");
        let outgoing = OutgoingCall::new(target).to_address(endpoint.transport, remote);
        let media = CallMedia::new(catalog(), MediaConfig::default());
        let call = place_call(
            &mut endpoint,
            script.account,
            outgoing,
            media,
            remote,
            Instant::now(),
        )
        .expect("a call handle");
        script.call = Some(call);
        script.original_codec = Some(Codec::Pcmu);

        let moved_to = |codec, direction| Event::Media {
            call,
            event: MediaEvent::Changed { codec, direction },
        };
        script.on_event(
            &mut endpoint,
            &moved_to(Codec::Pcma, Direction::SendRecv),
            Instant::now(),
        );
        assert!(
            !script.seen.has(Fact::CodecChanged),
            "a codec that moved before any hold counted as the change"
        );

        script.seen.saw(Fact::Held);
        script.on_event(
            &mut endpoint,
            &moved_to(Codec::Pcma, Direction::SendOnly),
            Instant::now(),
        );
        assert!(
            script.seen.has(Fact::CodecChanged),
            "the same change while held is the one this flow asked for"
        );
        assert!(script.seen.refused.is_none());

        script.on_event(
            &mut endpoint,
            &moved_to(Codec::Pcmu, Direction::SendRecv),
            Instant::now(),
        );
        assert!(
            script.seen.refused.is_some(),
            "a resume back onto the codec the call held on passed"
        );
    }

    /// A flow ends in the same event that queues its last request — a call
    /// that ends gives its binding back from `Script::finish` — and `drive`
    /// used to stop the moment the script said it was done, before anything
    /// else wrote the queue out. The binding then sat on the registrar until
    /// it expired: six of them from one run against Asterisk, whose lab
    /// endpoint allows ten, so a second run inside five minutes had its
    /// REGISTERs refused.
    #[test]
    fn a_flow_whose_call_ends_still_gives_its_binding_back() {
        let registrar = UdpSocket::bind(SocketAddr::new(LOOPBACK, 0)).expect("a registrar socket");
        let remote = registrar.local_addr().expect("bound");
        let (mut endpoint, mut script) = scripted(Flow::Call, remote);
        let until = Instant::now() + Duration::from_millis(2_500);
        let server = std::thread::spawn(move || busy_registrar(&registrar, until));

        drive(
            &mut endpoint,
            &mut script,
            Instant::now() + Duration::from_secs(2),
        );
        let requests = server.join().expect("the registrar's own thread");
        let methods: Vec<&str> = requests
            .iter()
            .filter_map(|request| request.split(' ').next())
            .collect();

        assert!(
            script.seen.has(Fact::Registered),
            "the binding was never granted: {methods:?}"
        );
        assert!(
            script.step == Step::Done && script.seen.has(Fact::Over),
            "the call was never refused: {methods:?}"
        );
        let invite = methods
            .iter()
            .position(|method| *method == "INVITE")
            .expect("an INVITE went out");
        assert!(
            methods[invite..].contains(&"REGISTER"),
            "the flow ended without giving its binding back: {methods:?}"
        );
    }

    /// An endpoint on loopback and a script for `flow` on it, built the way
    /// `run` builds them, against a far end at `remote`.
    pub(crate) fn scripted(flow: Flow, remote: SocketAddr) -> (Endpoint, Script) {
        let now = Instant::now();
        let mut endpoint = Endpoint::bind(
            seed(flow),
            media_seed(flow),
            SocketAddr::new(LOOPBACK, 0),
            catalog(),
            now,
        )
        .expect("binding on loopback");
        let account = endpoint
            .account("labuser", "labpass", "127.0.0.1", remote)
            .expect("an account");
        let script = Script::new(flow, account, "9000", "9001", "127.0.0.1", remote, now);
        (endpoint, script)
    }

    /// Every fact a call that dwells owes, so that the only thing left for
    /// the verdict to judge is the audio.
    fn a_call_that_did_everything_but_carry_audio(flow: Flow) -> Script {
        let (_endpoint, mut script) = scripted(flow, SocketAddr::new(LOOPBACK, 5060));
        for fact in [
            Fact::Registered,
            Fact::Up,
            Fact::Ours,
            Fact::Over,
            Fact::Encrypted,
        ] {
            script.seen.saw(fact);
        }
        script
    }

    /// `scripts/lab.sh` sets `SIPRAL_REQUIRE_AUDIO`, and every impairment
    /// profile's "audio survived it" rests on it: a call that connected and
    /// ended with nothing audible coming back is a failure, not a pass. The
    /// SRTP flow dwells on the same tone the plain call does, and a stream
    /// that negotiated SDES but never decrypted a frame is exactly what it
    /// exists to catch.
    #[test]
    fn a_call_that_heard_nothing_fails_when_audio_is_required() {
        let silent = Heard {
            sent: 100,
            received: 0,
            audible: 0,
            refused: 3,
            ..Heard::default()
        };
        for flow in [Flow::Call, Flow::Srtp] {
            let script = a_call_that_did_everything_but_carry_audio(flow);
            let verdict = script.verdict(silent, true);
            assert!(
                verdict
                    .as_ref()
                    .is_err_and(|why| why.contains("nothing audible came back")),
                "{flow:?} passed with nothing audible: {verdict:?}"
            );
            assert_eq!(
                script.verdict(silent, false),
                Ok(()),
                "{flow:?} failed on audio nobody asked for"
            );
            let heard = Heard {
                audible: 40,
                ..silent
            };
            assert_eq!(
                script.verdict(heard, true),
                Ok(()),
                "{flow:?} failed although the tone came back"
            );
        }
    }

    /// The DTLS flow's claim is about after the hold and the resume, the two
    /// re-offers that hand the roles back: a tone that came back only before
    /// them says the first handshake worked and nothing about the rest.
    #[test]
    fn a_dtls_call_heard_only_before_the_hold_fails_when_audio_is_required() {
        let mut script = a_call_that_did_everything_but_carry_audio(Flow::Dtls);
        script.seen.saw(Fact::Held);
        script.seen.saw(Fact::Resumed);
        script.audible_at_resume = Some(40);
        let before = Heard {
            sent: 300,
            received: 150,
            audible: 40,
            refused: 1,
            ..Heard::default()
        };
        let verdict = script.verdict(before, true);
        assert!(
            verdict
                .as_ref()
                .is_err_and(|why| why.contains("after the resume")),
            "{verdict:?}"
        );
        assert_eq!(script.verdict(before, false), Ok(()));
        let after = Heard {
            audible: 90,
            ..before
        };
        assert_eq!(script.verdict(after, true), Ok(()));
    }
}
