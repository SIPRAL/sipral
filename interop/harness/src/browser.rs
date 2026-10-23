// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! A call each way between the stack's WebRTC line and a browser: a headless
//! Chromium whose page is a phone made of JsSIP and the browser's own
//! `RTCPeerConnection` (`interop/browser/`), run beside this harness by
//! `scripts/lab.sh browser`.
//!
//! The account is a WebRTC line (`AccountSrtp::webrtc`) registered over UDP.
//! It calls the page's phone, hears it, and hangs up; then the page calls it,
//! it answers, hears it, and the page hangs up. Each end sends a tone of its
//! own, this one the harness's 444 Hz and the page a sine at
//! [`BROWSER_HZ`], so audio heard at each end is the other's and not an
//! echo: here it is counted in frames that hold the page's pitch
//! (`Media::listen_for`), and the page counts the harness's in its own.
//!
//! # Through Asterisk
//!
//! The page registers over Asterisk's secure WebSocket (`interop/wss/`) as
//! `labuser-browser`, a `webrtc=yes` endpoint, and this end as
//! `labuser-webrtc`. 9061 rings the page and 9062 rings this end, and
//! Asterisk bridges the two WebRTC legs: it ends ICE and DTLS-SRTP on each
//! and carries the audio between them, so this end's DTLS, ICE and SRTP meet
//! Asterisk's, and the page's meet Asterisk's too.
//!
//! # Through Kamailio
//!
//! The page registers over Kamailio's WebSocket on 8080 as `webrtc-browser`,
//! and this end as `webrtc-sipral`; each dials the other's user. The proxy
//! carries the signalling only, so the media goes between this end and
//! Chromium with nothing in the middle: Chromium's ICE agent, its DTLS and
//! its SRTP against this stack's. Both ends trickle (RFC 8838, RFC 8840):
//! this one in full, its offer and answer with the host candidate alone and
//! the end of its candidates in an INFO, since the lab's network has nothing
//! else to gather; the page with every candidate held back from its
//! descriptions and sent in INFOs, so what this end knows of Chromium's
//! candidates from signalling it learned by trickle alone.
//!
//! # What fails it
//!
//! The registration never granted; the page never reachable within
//! [`BROWSER_PATIENCE`]; either call coming up on a description that is not
//! a WebRTC line's, or with fewer than [`PITCHED_WANTED`] frames of the
//! page's tone; no DTLS suite or no ICE path reported; a call ended by the
//! wrong end; under trickle, nothing trickled in on either call or this end's
//! end of candidates never handed over.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sipral::{
    AccountId, AccountSrtp, CallEndReason, CallHandle, CallMedia, EndpointConfig, Event,
    IceTrickle, MediaConfig, MediaEvent, OutgoingCall, UaEvent,
};
use sipral_core::sdp::SessionDescription;

use crate::webrtc::{body, described};
use crate::{Endpoint, catalog, place_call, route_to, run_folded, uri};

/// The pitch of the page's tone (`interop/browser/run.mjs`'s `TONE_HZ`).
const BROWSER_HZ: f64 = 1_000.0;

/// Frames of the page's tone wanted on each call: half a second.
const PITCHED_WANTED: u32 = 25;

/// How long the page may take to come up and register: its container is
/// started just before this one, and Chromium is launched inside it.
const BROWSER_PATIENCE: Duration = Duration::from_secs(120);

/// How long before a call the page refused, or that nobody answered, is
/// placed again.
const RETRY: Duration = Duration::from_secs(2);

/// How long each call is listened to once its media is up.
const LISTEN: Duration = Duration::from_secs(6);

const PATIENCE: Duration = Duration::from_secs(20);

/// How long the page's own call may take to arrive once this end's first
/// call is over, and to be hung up once answered: the page listens four
/// seconds (`run.mjs`'s `LISTEN_MS`).
const PAGE_PATIENCE: Duration = Duration::from_secs(40);

/// The largest request sent as one datagram when no stream is coming
/// (`DatagramLimit::without_stream_bytes`), as `crate::webrtc` has it.
const UDP_ANYWAY: u32 = 1600;

/// This flow's own endpoint identity, through Asterisk and through Kamailio
/// (`main.rs`'s `tests::endpoint_identity_constants_are_distinct`).
pub(crate) const SEED: u8 = 214;
pub(crate) const MEDIA_SEED: u8 = 215;
pub(crate) const PROXY_SEED: u8 = 216;
pub(crate) const PROXY_MEDIA_SEED: u8 = 217;

/// Where one run of the flow goes.
pub(crate) struct Lab<'a> {
    /// `asterisk` or `kamailio`, the SIP domain too.
    pub(crate) server: &'a str,
    /// The server's SIP address over UDP.
    pub(crate) remote: SocketAddr,
    pub(crate) user: &'a str,
    pub(crate) pass: &'a str,
    /// What is dialled to reach the page: Asterisk's 9061, or its user at
    /// Kamailio.
    pub(crate) browser: &'a str,
    /// How this end trickles: not at all through Asterisk, which does not,
    /// and in full through Kamailio, where the far end is Chromium.
    pub(crate) trickle: IceTrickle,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Stage {
    Registering,
    Dialling,
    Listening,
    Hanging,
    Awaiting,
    Answered,
    Unregistering,
}

/// One call's story.
#[derive(Default)]
struct Leg {
    call: Option<CallHandle>,
    far: Option<SessionDescription>,
    path: Option<SocketAddr>,
    suite: Option<String>,
    trickled_in: u32,
    /// The end of this end's candidates was handed to the call to trickle.
    ended_out: bool,
}

/// Which of the two calls `call` is, if either.
fn leg_for<'l>(call: CallHandle, out_leg: &'l mut Leg, in_leg: &'l mut Leg) -> Option<&'l mut Leg> {
    if out_leg.call == Some(call) {
        Some(out_leg)
    } else if in_leg.call == Some(call) {
        Some(in_leg)
    } else {
        None
    }
}

impl Leg {
    fn new(call: CallHandle) -> Self {
        Self {
            call: Some(call),
            ..Self::default()
        }
    }

    fn said(&self, endpoint: &Endpoint, lab: &Lab<'_>) -> Result<String, String> {
        let far = self
            .far
            .as_ref()
            .ok_or("the far end's description never arrived")?;
        let lines = described(far)?;
        let candidates = far
            .media
            .iter()
            .flat_map(|stream| stream.attributes.iter())
            .filter(|attribute| attribute.name == "candidate")
            .count();
        let heard = self
            .call
            .and_then(|call| endpoint.media.get(&call))
            .map(crate::audio::Media::heard)
            .unwrap_or_default();
        if heard.pitched < PITCHED_WANTED {
            return Err(format!(
                "{} frames sent, {} received and only {} held the page's {BROWSER_HZ} Hz ({lines}; \
                 {candidates} candidates described, {} trickle INFOs in; ICE path {:?}, DTLS {:?})",
                heard.sent, heard.received, heard.pitched, self.trickled_in, self.path, self.suite
            ));
        }
        let path = self.path.ok_or("no ICE path was reported")?;
        let suite = self.suite.as_deref().ok_or("no DTLS suite was reported")?;
        if lab.trickle != IceTrickle::Off && self.trickled_in == 0 {
            return Err(format!(
                "trickling, and nothing was trickled in ({candidates} candidates described; {lines})"
            ));
        }
        Ok(format!(
            "{} sent, {} of the page's {BROWSER_HZ} Hz frames back; {lines}; {candidates} \
             candidates described, {} trickle INFOs in{}; ICE to {path}, {suite}",
            heard.sent,
            heard.pitched,
            self.trickled_in,
            if self.ended_out {
                ", the end of candidates trickled out"
            } else {
                ""
            }
        ))
    }
}

/// The account, bound and registered as a WebRTC line.
fn account(endpoint: &mut Endpoint, lab: &Lab<'_>, now: Instant) -> Result<AccountId, String> {
    let account = endpoint.account(lab.user, lab.pass, lab.server, lab.remote)?;
    let mut line = AccountSrtp::default();
    line.webrtc = Some(true);
    endpoint
        .engine
        .set_account_srtp(account, line)
        .map_err(|error| format!("the account would not be a WebRTC line: {error}"))?;
    if lab.trickle != IceTrickle::Off {
        endpoint.agent.accept_trickle_ice(true);
    }
    endpoint
        .agent
        .register(account, now)
        .map_err(|error| format!("cannot register: {error}"))?;
    Ok(account)
}

/// Under full trickle, hand the call the end of its candidates: the host
/// candidate its description carried is all the lab's network gives. Whether
/// it was handed.
fn end_candidates(
    endpoint: &mut Endpoint,
    lab: &Lab<'_>,
    call: CallHandle,
    now: Instant,
) -> Result<bool, String> {
    if lab.trickle != IceTrickle::Full {
        return Ok(false);
    }
    endpoint
        .engine
        .end_of_candidates(&mut endpoint.agent, call, now)
        .map_err(|error| format!("the end of candidates was not taken: {error}"))?;
    Ok(true)
}

/// Call the page, hear it, hang up; be called by it, hear it, and be hung up
/// on; give the binding back.
///
/// # Errors
/// The first thing that was not as it has to be.
#[allow(clippy::too_many_lines)]
pub(crate) fn run(lab: &Lab<'_>) -> Result<String, String> {
    let started = Instant::now();
    let mut config = EndpointConfig::default();
    config.datagram_limit.without_stream_bytes = Some(UDP_ANYWAY);
    let (seed, media_seed) = if lab.server == "asterisk" {
        (SEED, MEDIA_SEED)
    } else {
        (PROXY_SEED, PROXY_MEDIA_SEED)
    };
    let mut endpoint = Endpoint::bind_with(
        config,
        run_folded([seed; 32]),
        run_folded([media_seed; 32]),
        SocketAddr::new(route_to(lab.remote), 0),
        catalog(),
        started,
    )
    .map_err(|error| format!("cannot bind: {error}"))?;
    let account = account(&mut endpoint, lab, started)?;
    let media = |endpoint: &Endpoint| {
        CallMedia::new(
            endpoint
                .engine
                .account_catalog(account)
                .with_ice_trickle(lab.trickle),
            MediaConfig::default(),
        )
    };

    let mut stage = Stage::Registering;
    let mut since = started;
    let mut redial: Option<Instant> = None;
    let (mut out_leg, mut in_leg) = (Leg::default(), Leg::default());
    let mut said: Vec<String> = Vec::new();
    let mut story: Vec<String> = Vec::new();
    let mut refusals = 0_u32;

    loop {
        let now = Instant::now();
        if redial.is_some_and(|at| now >= at) {
            redial = None;
            let outgoing = OutgoingCall::new(uri(&format!("sip:{}@{}", lab.browser, lab.server))?)
                .to_address(endpoint.transport, lab.remote);
            let placing = media(&endpoint);
            let call = place_call(&mut endpoint, account, outgoing, placing, lab.remote, now)?;
            if let Some(socket) = endpoint.media.get_mut(&call) {
                socket.listen_for(BROWSER_HZ);
            }
            out_leg = Leg::new(call);
            out_leg.ended_out = end_candidates(&mut endpoint, lab, call, now)?;
        }
        for event in endpoint.pump(now) {
            match event {
                Event::Signalling(UaEvent::Registered { .. }) if stage == Stage::Registering => {
                    story.push("registered".to_owned());
                    stage = Stage::Dialling;
                    since = now;
                    redial = Some(now);
                }
                Event::Signalling(UaEvent::RegistrationFailed { reason, .. }) => {
                    return Err(format!("the registration failed: {reason:?}"));
                }
                Event::Signalling(UaEvent::TransportWanted {
                    protocol,
                    request_bytes,
                    limit_bytes,
                    ..
                }) => {
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
                }) if out_leg.call == Some(call) => {
                    out_leg.far = body(&response);
                }
                Event::Signalling(UaEvent::IncomingCall { call, request, .. })
                    if stage == Stage::Awaiting =>
                {
                    story.push("the page called".to_owned());
                    let mut leg = Leg::new(call);
                    leg.far = body(&request);
                    let local = endpoint.open_media(call, lab.remote, now)?;
                    if let Some(socket) = endpoint.media.get_mut(&call) {
                        socket.listen_for(BROWSER_HZ);
                    }
                    let answering = media(&endpoint);
                    endpoint
                        .engine
                        .answer_with(&mut endpoint.agent, call, local, answering, now)
                        .map_err(|error| format!("could not answer the page: {error}"))?;
                    leg.ended_out = end_candidates(&mut endpoint, lab, call, now)?;
                    in_leg = leg;
                    stage = Stage::Answered;
                    since = now;
                }
                Event::Signalling(UaEvent::TrickleIce { call, .. }) => {
                    if let Some(leg) = leg_for(call, &mut out_leg, &mut in_leg) {
                        leg.trickled_in += 1;
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::PathChosen { remote, .. },
                } => {
                    if let Some(leg) = leg_for(call, &mut out_leg, &mut in_leg) {
                        leg.path = Some(remote);
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::Secured { suite, .. },
                } => {
                    if let Some(leg) = leg_for(call, &mut out_leg, &mut in_leg) {
                        leg.suite = Some(format!("{suite:?}"));
                    }
                }
                Event::Media {
                    call,
                    event: MediaEvent::Started { .. },
                } if out_leg.call == Some(call) && stage == Stage::Dialling => {
                    story.push("the call to the page came up".to_owned());
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
                Event::Signalling(UaEvent::CallEnded {
                    call,
                    reason,
                    status,
                    ..
                }) => {
                    if out_leg.call == Some(call) && stage == Stage::Dialling {
                        // the page not up yet, or not registered yet: refused
                        // or unanswered, and placed again
                        refusals += 1;
                        if now > started + BROWSER_PATIENCE {
                            return Err(format!(
                                "the page was never reached: {reason:?} {status:?} [{}]",
                                story.join(", ")
                            ));
                        }
                        out_leg = Leg::default();
                        redial = Some(now + RETRY);
                    } else if out_leg.call == Some(call) && stage == Stage::Hanging {
                        story.push("this end's BYE answered".to_owned());
                        stage = Stage::Awaiting;
                        since = now;
                    } else if in_leg.call == Some(call) && stage == Stage::Answered {
                        if reason != CallEndReason::RemoteHangup {
                            return Err(format!(
                                "the page's call ended {reason:?}, not by its BYE [{}]",
                                story.join(", ")
                            ));
                        }
                        story.push("the page's BYE".to_owned());
                        said.push(format!("received: {}", in_leg.said(&endpoint, lab)?));
                        let _ = endpoint.agent.unregister(account, now);
                        stage = Stage::Unregistering;
                        since = now;
                    } else if out_leg.call == Some(call) || in_leg.call == Some(call) {
                        return Err(format!(
                            "a call ended part-way through: {reason:?} [{}]",
                            story.join(", ")
                        ));
                    }
                }
                Event::Signalling(UaEvent::Unregistered { .. })
                    if stage == Stage::Unregistering =>
                {
                    story.push("the binding was given back".to_owned());
                    if refusals > 0 {
                        story.push(format!("{refusals} calls placed before the page was up"));
                    }
                    return Ok(format!(
                        "   (through {}: {}; {})",
                        lab.server,
                        said.join("; "),
                        story.join(", ")
                    ));
                }
                _ => {}
            }
        }
        endpoint.run_media(now);
        endpoint.timers(now);
        endpoint.flush();

        match stage {
            Stage::Registering | Stage::Hanging | Stage::Unregistering
                if now > since + PATIENCE =>
            {
                return Err(format!("stuck {stage:?} [{}]", story.join(", ")));
            }
            Stage::Dialling if now > started + BROWSER_PATIENCE + PATIENCE => {
                return Err(format!("stuck {stage:?} [{}]", story.join(", ")));
            }
            Stage::Listening if now >= since + LISTEN => {
                let call = out_leg.call.ok_or("no call to the page")?;
                said.push(format!("placed: {}", out_leg.said(&endpoint, lab)?));
                let _ = endpoint.agent.hangup(call, now);
                stage = Stage::Hanging;
                since = now;
            }
            Stage::Awaiting | Stage::Answered if now > since + PAGE_PATIENCE => {
                return Err(format!("stuck {stage:?} [{}]", story.join(", ")));
            }
            _ => {}
        }
        if !endpoint.read_sip(Instant::now()) {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
