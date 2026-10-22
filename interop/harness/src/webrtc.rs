// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call each way on a PBX WebRTC line: Asterisk's `webrtc=yes` endpoint
//! (the lab's `labuser-webrtc`, and `labuser-webrtc-ws` over a WebSocket),
//! reached by an account the stack is told is a WebRTC line
//! (`AccountSrtp::webrtc`).
//!
//! The account registers, over UDP or over a WebSocket the stack opens on
//! the harness's TCP connection (RFC 7118, as `websocket` does it). It calls
//! Asterisk's echo (9008) with the account's own catalogue: the offer is
//! `UDP/TLS/RTP/SAVPF` with DTLS-SRTP, ICE, `a=rtcp-mux-only` and the stream
//! alone in a BUNDLE group, and the echo has to be heard. Then it calls 9051,
//! where the dialplan has Asterisk originate a call back to the account it
//! came from and send it to the echo, refusing the call that asked: the
//! harness answers the call Asterisk placed, out of the account's catalogue,
//! and has to hear the echo on that one too. Both calls are hung up, the
//! binding is given back, and a WebSocket is closed from this end.
//!
//! Each call counts its audio both ways: the frames this end sent, and the
//! audible frames the echo sent back, which are this end's own tone after a
//! trip through Asterisk. What each description said is reported beside it —
//! the profile, whether the far end bundled and tagged the stream, whether it
//! multiplexed, the path ICE chose and the suite DTLS agreed — so the lab line
//! says what Asterisk actually did and not only that it worked.
//!
//! # FreeSWITCH
//!
//! The same account shape registered at Kamailio (`labuser`) calls
//! FreeSWITCH's echo behind it (9008) over UDP, and that call alone: the lab
//! profile (`interop/freeswitch/lab_profile.xml`) answers a WebRTC line's
//! offer with its own DTLS-SRTP, ICE and BUNDLE lines and needs no profile
//! of its own for it. FreeSWITCH's WebSocket bindings, which are what a
//! browser would reach, are not part of the lab, and there is no dialplan
//! there that calls back.
//!
//! # What fails it
//!
//! The registration never granted, either call never coming up, a call
//! coming up on a description that is not a WebRTC line's (no
//! `UDP/TLS/RTP/SAVPF`, no `a=rtcp-mux`, no fingerprint), fewer than
//! [`AUDIBLE_WANTED`] audible frames back on either call, Asterisk never
//! calling back, a BYE never answered, or the WebSocket given up.

use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use sipral::{
    Account, AccountId, AccountSrtp, CallHandle, CallMedia, Credentials, EndpointConfig, Event,
    Input, MediaConfig, MediaEvent, OutgoingCall, TransportId, TransportProtocol, UaEvent,
    WebSocketTarget,
};
use sipral_core::msg::OwnedMessage;
use sipral_core::sdp::{MID_EXTENSION, SessionDescription, parse};

use crate::websocket::{Connection, WS};
use crate::{Endpoint, catalog, place_call, route_to, run_folded, uri};

/// `interop/asterisk/extensions.conf`'s echo.
const ECHO_EXTENSION: &str = "9008";
/// The extension that has Asterisk call the account back, into the echo.
const CALL_BACK_EXTENSION: &str = "9051";

/// This flow's own endpoint identity over UDP, and over the WebSocket
/// (`main.rs`'s `tests::endpoint_identity_constants_are_distinct`). One each:
/// the two runs share a process, and the second drawing the first's
/// `Call-ID`s, tags and branches would have Asterisk take its BYE for a
/// retransmission of the first run's and answer it over UDP.
pub(crate) const SEED: u8 = 252;
pub(crate) const MEDIA_SEED: u8 = 254;
pub(crate) const WS_SEED: u8 = 245;
pub(crate) const WS_MEDIA_SEED: u8 = 247;

const PATIENCE: Duration = Duration::from_secs(20);
const LISTEN: Duration = Duration::from_secs(3);
const ENDING: Duration = Duration::from_secs(5);

/// Audible frames wanted back from the echo on each call: half a second.
const AUDIBLE_WANTED: u32 = 25;

/// The largest request the UDP run sends as one datagram when no stream is
/// coming (`DatagramLimit::without_stream_bytes`): an authenticated INVITE
/// on a WebRTC line is about 1550 bytes.
const UDP_ANYWAY: u32 = 1600;

/// Where one run of the flow goes.
pub(crate) struct Lab<'a> {
    /// The SIP domain: `asterisk`, or `kamailio` for FreeSWITCH behind it.
    pub(crate) server: &'a str,
    /// The server's SIP address over UDP.
    pub(crate) remote: SocketAddr,
    /// Asterisk's WebSocket listener, for the run over a WebSocket; `None`
    /// for a run over UDP.
    pub(crate) websocket: Option<SocketAddr>,
    /// Whether the server is asked to call back ([`CALL_BACK_EXTENSION`],
    /// Asterisk's dialplan); FreeSWITCH's run places its call alone.
    pub(crate) call_back: bool,
    pub(crate) user: &'a str,
    pub(crate) pass: &'a str,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    Registering,
    Placing,
    Listening,
    Hanging,
    AskingBack,
    Answered,
    Ending,
    Unregistering,
    Closing,
}

/// What the server's description of one call said, as the report puts it:
/// refused unless it is a WebRTC line's, `UDP/TLS/RTP/SAVPF` multiplexed and
/// keyed by a fingerprint.
fn described(far: &SessionDescription) -> Result<String, String> {
    let Some(stream) = far
        .media
        .iter()
        .find(|stream| stream.media == "audio" && !stream.is_rejected())
    else {
        return Err("the far end's description has no audio stream".to_owned());
    };
    if stream.proto != "UDP/TLS/RTP/SAVPF" {
        return Err(format!("the far end's description is on {}", stream.proto));
    }
    if !stream.has_rtcp_mux() || stream.attribute("fingerprint").is_none() {
        return Err(
            "the far end's description does not multiplex or names no fingerprint".to_owned(),
        );
    }
    let mut said = vec![stream.proto.clone()];
    said.push(far.bundle_group().map_or_else(
        || "no BUNDLE".to_owned(),
        |tags| format!("BUNDLE {}", tags.join(" ")),
    ));
    said.push(format!("mid {}", stream.mid().unwrap_or("-")));
    if stream.extmap_id(MID_EXTENSION).is_some() {
        said.push("the MID extension".to_owned());
    }
    if stream.has_rtcp_mux_only() {
        said.push("mux only".to_owned());
    }
    said.push(
        if stream.attribute("ice-ufrag").is_some() {
            "ICE"
        } else {
            "no ICE"
        }
        .to_owned(),
    );
    if stream.attribute("msid").is_some() {
        said.push("msid".to_owned());
    }
    Ok(said.join(" "))
}

/// The description in a message's body.
fn body(message: &OwnedMessage) -> Option<SessionDescription> {
    parse(message.as_raw().body()).ok()
}

/// One call's story: the server's description — its answer to the call placed,
/// its offer on the call it placed — the path and suite the media settled on,
/// and its audio.
#[derive(Default)]
struct Leg {
    far: Option<SessionDescription>,
    path: Option<SocketAddr>,
    suite: Option<String>,
}

impl Leg {
    fn said(&self, endpoint: &Endpoint, call: CallHandle) -> Result<String, String> {
        let Some(far) = self.far.as_ref() else {
            return Err("the far end's description never arrived".to_owned());
        };
        let lines = described(far)?;
        let heard = endpoint.media.get(&call).map(crate::audio::Media::heard);
        let (sent, audible) = heard.map_or((0, 0), |heard| (heard.sent, heard.audible));
        if audible < AUDIBLE_WANTED {
            return Err(format!(
                "{sent} frames sent and only {audible} audible frames back ({lines})"
            ));
        }
        Ok(format!(
            "{sent} sent, {audible} audible back; {lines}; ICE to {}, {}",
            self.path
                .map_or_else(|| "no path chosen".to_owned(), |path| path.to_string()),
            self.suite.as_deref().unwrap_or("no DTLS suite reported"),
        ))
    }
}

/// The signalling under the account: the endpoint's own UDP socket, or a
/// WebSocket over the harness's TCP connection.
enum Signalling {
    Udp,
    WebSocket(Connection),
}

impl Signalling {
    fn flush(&mut self, endpoint: &mut Endpoint) -> Result<(), String> {
        match self {
            Self::Udp => {
                endpoint.flush();
                Ok(())
            }
            Self::WebSocket(connection) => connection.flush(endpoint),
        }
    }

    fn read(&mut self, endpoint: &mut Endpoint, now: Instant) -> Result<bool, String> {
        let arrived = match self {
            Self::Udp => false,
            Self::WebSocket(connection) => connection.read(endpoint, now)?,
        };
        Ok(endpoint.read_sip(now) || arrived)
    }
}

/// The account, registered on whichever transport `lab` names.
fn account(
    endpoint: &mut Endpoint,
    lab: &Lab<'_>,
    now: Instant,
) -> Result<(AccountId, Signalling, TransportId, SocketAddr), String> {
    let Some(websocket) = lab.websocket else {
        let account = endpoint.account(lab.user, lab.pass, lab.server, lab.remote)?;
        return Ok((account, Signalling::Udp, endpoint.transport, lab.remote));
    };
    let socket = TcpStream::connect_timeout(&websocket, Duration::from_secs(5))
        .map_err(|error| format!("cannot connect to {websocket}: {error}"))?;
    socket
        .set_nonblocking(true)
        .map_err(|error| format!("cannot make the connection non-blocking: {error}"))?;
    let _ = socket.set_nodelay(true);
    let local = socket
        .local_addr()
        .map_err(|error| format!("the connection has no address: {error}"))?;
    let account = Account::new(
        uri(&format!("sip:{}@{}", lab.user, lab.server))?,
        uri(&format!("sip:{};transport=ws", lab.server))?,
        uri(&format!("sip:{}@{local}", lab.user))?,
        WS,
        websocket,
    )
    .credentials(Credentials::new(lab.user, lab.pass))
    .expires(Duration::from_secs(300));
    let target = WebSocketTarget::new(&format!("{}:{}", lab.server, websocket.port()), "/ws")
        .map_err(|error| format!("a target the stack refused: {error}"))?;
    endpoint.agent.set_websocket_target(websocket, target);
    let account = endpoint.agent.add_account(account);
    endpoint
        .agent
        .receive(
            Input::TransportBound {
                transport: WS,
                protocol: TransportProtocol::Ws,
                local,
                remote: Some(websocket),
            },
            now,
        )
        .map_err(|error| format!("cannot bind the WebSocket: {error}"))?;
    let connection = Connection {
        socket,
        inbox: vec![0_u8; 65_535],
    };
    Ok((account, Signalling::WebSocket(connection), WS, websocket))
}

/// Register as a WebRTC line, call the echo and hear it, and where
/// [`Lab::call_back`] says so have Asterisk call back and hear the echo on
/// that call too; hang up, give the binding back.
///
/// # Errors
/// The first thing that was not as it has to be.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(lab: &Lab<'_>) -> Result<String, String> {
    let now = Instant::now();
    // over UDP the INVITE that answers the server's challenge is past RFC 3261
    // §18.1.1's 1300 bytes, and this harness opens no TCP: the stack is told a
    // request up to UDP_ANYWAY may still go as one datagram once no stream is
    // coming, and the `TransportWanted` below says none is
    let mut config = EndpointConfig::default();
    if lab.websocket.is_none() {
        config.datagram_limit.without_stream_bytes = Some(UDP_ANYWAY);
    }
    let (seed, media_seed) = if lab.websocket.is_some() {
        (WS_SEED, WS_MEDIA_SEED)
    } else {
        (SEED, MEDIA_SEED)
    };
    let mut endpoint = Endpoint::bind_with(
        config,
        run_folded([seed; 32]),
        run_folded([media_seed; 32]),
        SocketAddr::new(route_to(lab.remote), 0),
        catalog(),
        now,
    )
    .map_err(|error| format!("cannot bind: {error}"))?;
    let (account, mut signalling, transport, server) = account(&mut endpoint, lab, now)?;
    let mut line = AccountSrtp::default();
    line.webrtc = Some(true);
    endpoint
        .engine
        .set_account_srtp(account, line)
        .map_err(|error| format!("the account would not be a WebRTC line: {error}"))?;
    endpoint
        .agent
        .register(account, now)
        .map_err(|error| format!("cannot register: {error}"))?;

    let mut stage = Stage::Registering;
    let mut since = now;
    let (mut placed, mut asked, mut back): (
        Option<CallHandle>,
        Option<CallHandle>,
        Option<CallHandle>,
    ) = (None, None, None);
    let (mut out_leg, mut in_leg) = (Leg::default(), Leg::default());
    let mut said = Vec::new();
    let mut story: Vec<String> = Vec::new();
    let dial = |endpoint: &mut Endpoint, extension: &str, now: Instant| {
        let media = CallMedia::new(
            endpoint.engine.account_catalog(account),
            MediaConfig::default(),
        );
        let outgoing = OutgoingCall::new(uri(&format!("sip:{extension}@{}", lab.server))?)
            .to_address(transport, server);
        place_call(endpoint, account, outgoing, media, server, now)
    };

    loop {
        let now = Instant::now();
        signalling.flush(&mut endpoint)?;
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) if stage == Stage::Registering => {
                    story.push("registered".to_owned());
                    placed = Some(dial(&mut endpoint, ECHO_EXTENSION, now)?);
                    stage = Stage::Placing;
                    since = now;
                }
                Event::Signalling(UaEvent::RegistrationFailed { reason, .. }) => {
                    return Err(format!("the registration failed: {reason:?}"));
                }
                Event::Signalling(UaEvent::TransportWanted {
                    protocol,
                    request_bytes,
                    limit_bytes,
                    ..
                }) if transport != WS => {
                    story.push(format!(
                        "a request of {request_bytes} bytes, past {limit_bytes}, went as one \
                         datagram: no {protocol:?} to the server"
                    ));
                    endpoint.agent.stream_unavailable(now);
                }
                Event::Signalling(UaEvent::CallConfirmed {
                    call,
                    response: Some(response),
                    ..
                }) if Some(call) == placed => {
                    out_leg.far = body(&response);
                }
                Event::Signalling(UaEvent::IncomingCall { call, request, .. })
                    if stage == Stage::AskingBack =>
                {
                    story.push("Asterisk called back".to_owned());
                    in_leg.far = body(&request);
                    let local = endpoint.open_media(call, lab.remote, now)?;
                    endpoint
                        .engine
                        .answer(&mut endpoint.agent, call, local, now)
                        .map_err(|error| format!("could not answer the call back: {error}"))?;
                    back = Some(call);
                    stage = Stage::Answered;
                    since = now;
                }
                Event::Media {
                    call,
                    event: MediaEvent::PathChosen { remote, .. },
                } => {
                    let leg = if Some(call) == back {
                        &mut in_leg
                    } else {
                        &mut out_leg
                    };
                    leg.path = Some(remote);
                }
                Event::Media {
                    call,
                    event: MediaEvent::Secured { suite, .. },
                } => {
                    let leg = if Some(call) == back {
                        &mut in_leg
                    } else {
                        &mut out_leg
                    };
                    leg.suite = Some(format!("{suite:?}"));
                }
                Event::Media {
                    call,
                    event: MediaEvent::Started { .. },
                } if Some(call) == placed && stage == Stage::Placing => {
                    story.push("the call to the echo came up".to_owned());
                    stage = Stage::Listening;
                    since = now;
                }
                Event::Media {
                    call,
                    event: MediaEvent::Failed(error),
                } => {
                    return Err(format!(
                        "the media of call {call:?} failed: {error} [{}]",
                        story.join(", ")
                    ));
                }
                Event::Signalling(UaEvent::CallEnded { call, reason, .. }) => {
                    if Some(call) == placed && stage == Stage::Hanging && !lab.call_back {
                        story.push("the call ended".to_owned());
                        let _ = endpoint.agent.unregister(account, now);
                        stage = Stage::Unregistering;
                        since = now;
                    } else if Some(call) == placed && stage == Stage::Hanging {
                        story.push("the first call ended".to_owned());
                        let trigger = dial(&mut endpoint, CALL_BACK_EXTENSION, now)?;
                        asked = Some(trigger);
                        stage = Stage::AskingBack;
                        since = now;
                    } else if Some(call) == asked {
                        story.push(format!("the call that asked ended {reason}"));
                    } else if Some(call) == back && stage == Stage::Ending {
                        story.push("the call back ended".to_owned());
                        let _ = endpoint.agent.unregister(account, now);
                        stage = Stage::Unregistering;
                        since = now;
                    } else if Some(call) == placed || Some(call) == back {
                        return Err(format!(
                            "a call ended part-way through: {reason} [{}]",
                            story.join(", ")
                        ));
                    }
                }
                Event::Signalling(UaEvent::Unregistered { .. })
                    if stage == Stage::Unregistering =>
                {
                    story.push("the binding was given back".to_owned());
                    if transport == WS {
                        endpoint.agent.close_websocket(WS, now);
                        stage = Stage::Closing;
                        since = now;
                    } else {
                        return Ok(report(lab, &said, &story));
                    }
                }
                Event::Signalling(UaEvent::FlowFailed { transport: failed })
                    if failed == WS && stage == Stage::Closing =>
                {
                    let closed = endpoint
                        .agent
                        .websocket_failure(WS)
                        .is_some_and(|(_, why)| why == "closed by this end");
                    if !closed {
                        return Err(format!("the close was not answered [{}]", story.join(", ")));
                    }
                    story.push("the WebSocket closed both ways".to_owned());
                    return Ok(report(lab, &said, &story));
                }
                _ => {}
            }
        }
        if transport == WS
            && let Some((_, why)) = endpoint
                .agent
                .websocket_failure(WS)
                .filter(|_| stage != Stage::Closing)
        {
            return Err(format!(
                "the stack gave the WebSocket up: {why} [{}]",
                story.join(", ")
            ));
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        signalling.flush(&mut endpoint)?;

        match stage {
            Stage::Registering | Stage::Placing | Stage::AskingBack if now > since + PATIENCE => {
                return Err(format!("stuck {stage:?} [{}]", story.join(", ")));
            }
            Stage::Listening if now >= since + LISTEN => {
                let call = placed.ok_or("no call to the echo")?;
                said.push(format!("placed: {}", out_leg.said(&endpoint, call)?));
                let _ = endpoint.agent.hangup(call, now);
                stage = Stage::Hanging;
                since = now;
            }
            Stage::Answered if now >= since + LISTEN => {
                let call = back.ok_or("no call back")?;
                said.push(format!("received: {}", in_leg.said(&endpoint, call)?));
                let _ = endpoint.agent.hangup(call, now);
                stage = Stage::Ending;
                since = now;
            }
            Stage::Hanging | Stage::Ending | Stage::Unregistering | Stage::Closing
                if now > since + ENDING =>
            {
                return Err(format!("stuck {stage:?} [{}]", story.join(", ")));
            }
            _ => {}
        }
        if !signalling.read(&mut endpoint, Instant::now())? {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The line the lab prints for a run that passed.
fn report(lab: &Lab<'_>, said: &[String], story: &[String]) -> String {
    format!(
        "   (over {}: {}; {})",
        if lab.websocket.is_some() {
            "a WebSocket"
        } else {
            "UDP"
        },
        said.join("; "),
        story.join(", ")
    )
}
