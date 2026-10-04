// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! End-of-call voice quality reporting: the SIP event package RFC 6035
//! defines, carried by a PUBLISH (RFC 3903) rather than the NOTIFY that
//! document's own examples use — SS3 leaves the choice of transport to the
//! implementation ("this document does not mandate ... a specific method of
//! communicating the [event package's] data"), and a one-shot report on
//! call end has no subscriber to notify, only a collector to tell.
//!
//! One report per call, sent once its media has stopped and never retried:
//! §5's own security section already expects "a burst of ... event
//! notifications" at the end of a call and asks a collector to be built for
//! it, and a report queued for retry would be exactly the burst multiplied.
//! The figures it carries are RFC 3611's own VoIP Metrics block — this
//! crate depends on nothing that measures RTP, so every number in
//! [`QualityReportMetrics`] is the caller's to supply.
//!
//! The `LocalMetrics` set is always written. `RemoteMetrics` is "the same
//! metrics ... but reported for or by the node connected via the
//! interface" (SS4.6), i.e. what the *far end* measured about *this*
//! stream, and the far end says so in its own RTCP XR VoIP Metrics block
//! (RFC 3611 SS4.7) about this end's source: the set is written from the
//! last such block when the call received one
//! ([`QualityReportMetrics::remote`]), and left out when it did not, since
//! a set of zeros under that name would claim a measurement nobody made.

use std::fmt::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use sipral_core::endpoint::OutgoingRequest;
use sipral_core::msg::HeaderName;
use sipral_core::msg::Method;

use crate::account::AccountId;
use crate::agent::UserAgent;
use crate::call::{CallHandle, CallIdentity, Direction};
use crate::error::UaError;

/// RFC 6035 SS4.1: the event package this report is published under.
const EVENT_PACKAGE: &[u8] = b"vq-rtcpxr";

/// RFC 6035 SS4.5: the body's MIME type.
const CONTENT_TYPE: &[u8] = b"application/vq-rtcpxr";

/// How many calls' worth of [`EndedCall`] snapshot [`UserAgent::finish`]
/// (`calls.rs`) is allowed to hold onto at once. A call whose account asked
/// for a report but that this stack never calls
/// [`UserAgent::send_quality_report`] about — refused before it was
/// answered, cancelled, any call the facade above this crate never gave a
/// media session — leaves its entry here unconsumed, so the count is capped
/// and the oldest entry evicted rather than kept for the rest of the
/// process's life.
const SNAPSHOT_CAP: usize = 32;

/// What [`UserAgent::send_quality_report`] needs to know about a call that
/// [`UserAgent::calls`] no longer does.
///
/// `finish` (`calls.rs`) queues the `CallEnded` event a call's end is
/// reported through and then, in the same breath, forgets the call: `From`,
/// `To`, `Call-ID` and which account it belonged to are gone from
/// [`UserAgent::calls`] before the facade above this crate ever gets to
/// react to that event by calling `send_quality_report` about it. This is
/// the snapshot of exactly those few facts, taken the moment before they
/// would otherwise be lost, and only for a call whose account has
/// something to publish to at all (`stash_ended_call`, below).
#[derive(Clone, Debug)]
pub(crate) struct EndedCall {
    pub(crate) account: AccountId,
    pub(crate) identity: CallIdentity,
    pub(crate) direction: Direction,
}

/// The RFC 3611 VoIP Metrics figures this crate has no way to measure
/// itself, exactly as `sipral_rtp::VoipMetricsBlock` and the codec that was
/// active carry them. Kept as plain scalars rather than a dependency on
/// `sipral-rtp`'s own types: this crate is signalling, and nothing in it
/// otherwise names an RTP concept.
#[derive(Clone, Debug)]
pub struct QualityReportMetrics {
    /// Where this end's RTP arrived, and the SSRC it was sent under.
    pub local_addr: SocketAddr,
    /// Ours.
    pub local_ssrc: u32,
    /// Where this end sent RTP, and the SSRC the far end used.
    pub remote_addr: SocketAddr,
    /// Theirs.
    pub remote_ssrc: u32,
    /// When the stream started.
    pub start: SystemTime,
    /// When it ended — normally "now" at the point the call went down.
    pub stop: SystemTime,
    /// The RTP payload type in use, most recently.
    pub payload_type: u8,
    /// A short codec name, e.g. `"PCMU"` — RFC 6035 SS4.6.1's `PayloadDesc`,
    /// which "SHOULD use the IANA registry for media-type names".
    pub payload_desc: &'static str,
    /// The codec's clock rate, in Hertz.
    pub sample_rate: u32,
    /// RFC 3611 SS4.7.1's loss rate, as its own 256ths.
    pub loss_rate: u8,
    /// RFC 3611 SS4.7.1's discard rate, as its own 256ths.
    pub discard_rate: u8,
    /// RFC 3611 SS4.7.2's burst density, as its own 256ths.
    pub burst_density: u8,
    /// RFC 3611 SS4.7.2's mean burst duration, in milliseconds.
    pub burst_duration_ms: u16,
    /// RFC 3611 SS4.7.2's gap density, as its own 256ths.
    pub gap_density: u8,
    /// RFC 3611 SS4.7.2's mean gap duration, in milliseconds.
    pub gap_duration_ms: u16,
    /// RFC 3611 SS4.7.2's `Gmin`.
    pub gmin: u8,
    /// RFC 3611 SS4.7.3's round-trip delay, in milliseconds.
    pub round_trip_delay_ms: u16,
    /// RFC 3611 SS4.7.3's end-system delay, in milliseconds.
    pub end_system_delay_ms: u16,
    /// RFC 3611 SS4.7.6's jitter buffer adaptive flag: `0` unknown, `1`
    /// reserved, `2` non-adaptive, `3` adaptive.
    pub jitter_buffer_adaptive: u8,
    /// RFC 3611 SS4.7.6's jitter buffer adjustment rate, `0..=15`.
    pub jitter_buffer_rate: u8,
    /// RFC 3611 SS4.7.7's nominal jitter buffer delay, in milliseconds.
    pub jitter_buffer_nominal_ms: u16,
    /// RFC 3611 SS4.7.7's current maximum jitter buffer delay, in
    /// milliseconds.
    pub jitter_buffer_maximum_ms: u16,
    /// RFC 3611 SS4.7.7's absolute maximum jitter buffer delay, in
    /// milliseconds.
    pub jitter_buffer_abs_max_ms: u16,
    /// RFC 3611 SS4.7.5's R factor, `0..=100`, or `None` for its own `127`
    /// "unavailable" sentinel.
    pub r_factor: Option<u8>,
    /// RFC 3611 SS4.7.5's MOS-LQ, in tenths of a mean opinion score
    /// (`14..=50`), or `None` for "unavailable".
    pub mos_lq_x10: Option<u8>,
    /// RFC 3611 SS4.7.5's MOS-CQ, in tenths, or `None` for "unavailable".
    pub mos_cq_x10: Option<u8>,
    /// What the far end measured of the stream this end sent it, from the
    /// last RTCP XR VoIP Metrics block it sent about this end's source
    /// (`local_ssrc`): the `RemoteMetrics` set. `None` when no such block
    /// arrived in the call, and the set is left out.
    pub remote: Option<RemoteQualityMetrics>,
}

/// The far end's own RFC 3611 SS4.7 VoIP Metrics block about the stream this
/// end sent, as scalars for the same reason [`QualityReportMetrics`] is. The
/// session's span and its codec are the call's, and are written from
/// [`QualityReportMetrics`].
#[derive(Clone, Debug)]
pub struct RemoteQualityMetrics {
    /// RFC 3611 SS4.7.1's loss rate, as its own 256ths.
    pub loss_rate: u8,
    /// RFC 3611 SS4.7.1's discard rate, as its own 256ths.
    pub discard_rate: u8,
    /// RFC 3611 SS4.7.2's burst density, as its own 256ths.
    pub burst_density: u8,
    /// RFC 3611 SS4.7.2's mean burst duration, in milliseconds.
    pub burst_duration_ms: u16,
    /// RFC 3611 SS4.7.2's gap density, as its own 256ths.
    pub gap_density: u8,
    /// RFC 3611 SS4.7.2's mean gap duration, in milliseconds.
    pub gap_duration_ms: u16,
    /// RFC 3611 SS4.7.2's `Gmin`.
    pub gmin: u8,
    /// RFC 3611 SS4.7.3's round-trip delay, in milliseconds, as the far end
    /// measured it.
    pub round_trip_delay_ms: u16,
    /// RFC 3611 SS4.7.3's end-system delay, in milliseconds.
    pub end_system_delay_ms: u16,
    /// RFC 3611 SS4.7.4's signal level, in dBm0, or `None` for its
    /// "unavailable" sentinel.
    pub signal_level_dbm0: Option<i8>,
    /// RFC 3611 SS4.7.4's noise level, in dBm0, or `None`.
    pub noise_level_dbm0: Option<i8>,
    /// RFC 3611 SS4.7.4's residual echo return loss, in dB, or `None`.
    pub rerl_db: Option<u8>,
    /// RFC 3611 SS4.7.6's jitter buffer adaptive flag.
    pub jitter_buffer_adaptive: u8,
    /// RFC 3611 SS4.7.6's jitter buffer adjustment rate, `0..=15`.
    pub jitter_buffer_rate: u8,
    /// RFC 3611 SS4.7.7's nominal jitter buffer delay, in milliseconds.
    pub jitter_buffer_nominal_ms: u16,
    /// RFC 3611 SS4.7.7's current maximum jitter buffer delay, in
    /// milliseconds.
    pub jitter_buffer_maximum_ms: u16,
    /// RFC 3611 SS4.7.7's absolute maximum jitter buffer delay, in
    /// milliseconds.
    pub jitter_buffer_abs_max_ms: u16,
    /// RFC 3611 SS4.7.5's R factor, or `None` for "unavailable".
    pub r_factor: Option<u8>,
    /// RFC 3611 SS4.7.5's external R factor, or `None`.
    pub ext_r_factor: Option<u8>,
    /// RFC 3611 SS4.7.5's MOS-LQ, in tenths, or `None`.
    pub mos_lq_x10: Option<u8>,
    /// RFC 3611 SS4.7.5's MOS-CQ, in tenths, or `None`.
    pub mos_cq_x10: Option<u8>,
}

/// One `Metrics` set's figures (SS4.6.1), whichever end measured them.
struct Figures {
    jitter_buffer: [u16; 5],
    loss_rate: u8,
    discard_rate: u8,
    burst_density: u8,
    burst_duration_ms: u16,
    gap_density: u8,
    gap_duration_ms: u16,
    gmin: u8,
    round_trip_delay_ms: u16,
    end_system_delay_ms: u16,
    signal: (Option<i8>, Option<i8>, Option<u8>),
    r_factor: Option<u8>,
    ext_r_factor: Option<u8>,
    mos_lq_x10: Option<u8>,
    mos_cq_x10: Option<u8>,
}

impl Figures {
    fn local(metrics: &QualityReportMetrics) -> Self {
        Self {
            jitter_buffer: [
                u16::from(metrics.jitter_buffer_adaptive),
                u16::from(metrics.jitter_buffer_rate),
                metrics.jitter_buffer_nominal_ms,
                metrics.jitter_buffer_maximum_ms,
                metrics.jitter_buffer_abs_max_ms,
            ],
            loss_rate: metrics.loss_rate,
            discard_rate: metrics.discard_rate,
            burst_density: metrics.burst_density,
            burst_duration_ms: metrics.burst_duration_ms,
            gap_density: metrics.gap_density,
            gap_duration_ms: metrics.gap_duration_ms,
            gmin: metrics.gmin,
            round_trip_delay_ms: metrics.round_trip_delay_ms,
            end_system_delay_ms: metrics.end_system_delay_ms,
            // nothing upstream of this crate reports a signal or noise level
            // or a residual echo return loss for this end
            signal: (None, None, None),
            r_factor: metrics.r_factor,
            ext_r_factor: None,
            mos_lq_x10: metrics.mos_lq_x10,
            mos_cq_x10: metrics.mos_cq_x10,
        }
    }

    fn remote(metrics: &RemoteQualityMetrics) -> Self {
        Self {
            jitter_buffer: [
                u16::from(metrics.jitter_buffer_adaptive),
                u16::from(metrics.jitter_buffer_rate),
                metrics.jitter_buffer_nominal_ms,
                metrics.jitter_buffer_maximum_ms,
                metrics.jitter_buffer_abs_max_ms,
            ],
            loss_rate: metrics.loss_rate,
            discard_rate: metrics.discard_rate,
            burst_density: metrics.burst_density,
            burst_duration_ms: metrics.burst_duration_ms,
            gap_density: metrics.gap_density,
            gap_duration_ms: metrics.gap_duration_ms,
            gmin: metrics.gmin,
            round_trip_delay_ms: metrics.round_trip_delay_ms,
            end_system_delay_ms: metrics.end_system_delay_ms,
            signal: (
                metrics.signal_level_dbm0,
                metrics.noise_level_dbm0,
                metrics.rerl_db,
            ),
            r_factor: metrics.r_factor,
            ext_r_factor: metrics.ext_r_factor,
            mos_lq_x10: metrics.mos_lq_x10,
            mos_cq_x10: metrics.mos_cq_x10,
        }
    }
}

impl UserAgent {
    /// Send `call`'s end-of-session voice quality report, if the account it
    /// belongs to asked for one ([`crate::Account::quality_report_uri`]).
    ///
    /// `Ok(false)` for the no-op — the call is not known, has no account,
    /// or the account named no collector — so the caller does not have to
    /// check first. `Ok(true)` once a PUBLISH has actually gone out: it
    /// closes its own published state at once (RFC 3903 SS3's initial
    /// `Expires: 0`), since this report describes a call that has already
    /// ended and nothing here refreshes it, and this method neither waits
    /// for nor reports on whatever answers it — a collector that never
    /// answers has cost this end one UDP datagram, not a retry loop.
    ///
    /// # Errors
    /// Whatever [`sipral_core::endpoint::Endpoint::request`] refuses the
    /// PUBLISH for: a transport this end no longer has bound, most likely.
    /// The caller decides whether that is worth surfacing; a call that has
    /// already ended is not going to un-end over it.
    pub fn send_quality_report(
        &mut self,
        call: CallHandle,
        metrics: &QualityReportMetrics,
        now: Instant,
    ) -> Result<bool, UaError> {
        // The ordinary case is the call already forgotten: `finish`
        // (`calls.rs`) queues the `CallEnded` event that tells the facade
        // above this crate to call this method, and forgets the call in the
        // same breath, before that event is ever drained. `self.calls` is
        // still checked first rather than only the snapshot, so that a call
        // asked about while it is still up — a test, or a future mid-call
        // report — reads the live state rather than a stale copy of it.
        let (account_id, identity, direction) = if let Some(held) = self.calls.get(&call) {
            let Some(account_id) = held.account else {
                return Ok(false);
            };
            let direction = held.direction;
            let Some(identity) = self.call_identity(call) else {
                return Ok(false);
            };
            (account_id, identity, direction)
        } else if let Some(snapshot) = self.quality_report_snapshots.remove(&call) {
            self.quality_report_order.retain(|held| *held != call);
            (snapshot.account, snapshot.identity, snapshot.direction)
        } else {
            return Ok(false);
        };
        let Some(account) = self.accounts.get(&account_id) else {
            return Ok(false);
        };
        let Some(collector) = account.quality_report() else {
            return Ok(false);
        };

        let mut to = Vec::with_capacity(collector.as_bytes().len() + 2);
        to.push(b'<');
        to.extend_from_slice(collector.as_bytes());
        to.push(b'>');

        let Some((transport, remote)) = account.destination() else {
            return Ok(false);
        };
        let request = OutgoingRequest::new(Method::Publish, collector.clone(), transport, remote)
            .to(&to)
            .from(&account.sender_value())
            .header(HeaderName::Event, EVENT_PACKAGE)
            .header(HeaderName::Expires, b"0")
            .body(CONTENT_TYPE, Arc::from(body(&identity, direction, metrics)));

        self.endpoint.request(&request, now)?;
        Ok(true)
    }

    /// Keep what [`UserAgent::send_quality_report`] will need about `call`
    /// past the `forget` (`calls.rs`) that is about to remove it from
    /// [`UserAgent::calls`] — called from `finish`, immediately before that.
    ///
    /// A no-op unless there is a reason not to be one: a call with no
    /// account, or one whose account never asked for a report
    /// ([`Account::quality_report`](crate::account::Account::quality_report)),
    /// has nothing this cache should remember, since nothing will ever ask
    /// it. Every account that did ask is still bounded by [`SNAPSHOT_CAP`],
    /// the oldest entry evicted first: a call that is rejected, cancelled,
    /// or otherwise never reaches a media session for the facade above this
    /// crate to call `send_quality_report` about leaves its entry here
    /// unconsumed, and nothing else here ever removes it.
    pub(crate) fn stash_ended_call(&mut self, call: CallHandle) {
        let Some(held) = self.calls.get(&call) else {
            return;
        };
        let Some(account_id) = held.account else {
            return;
        };
        if self
            .accounts
            .get(&account_id)
            .is_none_or(|account| account.quality_report().is_none())
        {
            return;
        }
        let direction = held.direction;
        let Some(identity) = self.call_identity(call) else {
            return;
        };
        if self.quality_report_snapshots.len() >= SNAPSHOT_CAP
            && let Some(oldest) = self.quality_report_order.pop_front()
        {
            self.quality_report_snapshots.remove(&oldest);
        }
        self.quality_report_order.push_back(call);
        self.quality_report_snapshots.insert(
            call,
            EndedCall {
                account: account_id,
                identity,
                direction,
            },
        );
    }
}

/// One party's identity for the `LocalID`/`RemoteID` lines: which of
/// [`CallIdentity`]'s two URIs is ours depends on which end placed the
/// call, since it always carries the `From` and `To` of the request that
/// opened it, whichever side wrote that request.
fn parties(identity: &CallIdentity, direction: Direction) -> (&[u8], &[u8]) {
    match direction {
        Direction::Outgoing => (&identity.from_uri, &identity.to_uri),
        Direction::Incoming => (&identity.to_uri, &identity.from_uri),
    }
}

/// The RFC 6035 SS4.6.1 body: one `VQSessionReport:CallTerm`, its
/// `SessionInfo`, a `LocalMetrics` block built from `metrics`, and a
/// `RemoteMetrics` block from what the far end reported, when it did.
fn body(identity: &CallIdentity, direction: Direction, metrics: &QualityReportMetrics) -> Vec<u8> {
    let (local, remote) = parties(identity, direction);
    let mut out = String::new();
    out.push_str("VQSessionReport: CallTerm\r\n");
    write_header(
        &mut out,
        "CallID",
        &String::from_utf8_lossy(&identity.call_id),
    );
    write_header(&mut out, "LocalID", &String::from_utf8_lossy(local));
    write_header(&mut out, "RemoteID", &String::from_utf8_lossy(remote));
    // OrigID: "identifies the endpoint which originated the session" --
    // the `From` of the request that opened it, whichever end sent that
    // request, which is exactly what `CallIdentity::from_uri` already is.
    write_header(
        &mut out,
        "OrigID",
        &String::from_utf8_lossy(&identity.from_uri),
    );
    write_header(
        &mut out,
        "LocalAddr",
        &addr_line(metrics.local_addr, metrics.local_ssrc),
    );
    write_header(
        &mut out,
        "RemoteAddr",
        &addr_line(metrics.remote_addr, metrics.remote_ssrc),
    );
    out.push_str("LocalMetrics:\r\n");
    write_metrics(&mut out, metrics, &Figures::local(metrics));
    if let Some(remote) = &metrics.remote {
        // the same session and the same codec: this stack sends what it
        // negotiated to receive, and the far end measured it over the
        // same span
        out.push_str("RemoteMetrics:\r\n");
        write_metrics(&mut out, metrics, &Figures::remote(remote));
    }
    out.into_bytes()
}

fn write_header(out: &mut String, name: &str, value: &str) {
    out.push_str(name);
    out.push_str(": ");
    out.push_str(value);
    out.push_str("\r\n");
}

/// `LocalAddr`/`RemoteAddr`'s value (SS4.6.1's `IPAddress WSP Port WSP
/// Ssrc`): the address and SSRC of one end of the RTP stream being
/// measured.
fn addr_line(addr: SocketAddr, ssrc: u32) -> String {
    format!("IP={} PORT={} SSRC=0x{:x}", addr.ip(), addr.port(), ssrc)
}

/// One `Metrics` block (SS4.6.1): `Timestamps` and `SessionDesc` from the
/// session, then every optional line there is a figure for in `figures`,
/// in the order the worked example of SS4.7.1 uses. A line with no figure
/// at all, `Signal` for this end's own set, is left out, as the grammar
/// allows and SS4.6 asks ("exclude any parameters for which values are not
/// available").
fn write_metrics(out: &mut String, metrics: &QualityReportMetrics, figures: &Figures) {
    let _ = write!(
        out,
        "Timestamps:START={} STOP={}\r\n",
        rfc3339(metrics.start),
        rfc3339(metrics.stop)
    );
    let _ = write!(
        out,
        "SessionDesc:PT={} PD={} SR={}\r\n",
        metrics.payload_type, metrics.payload_desc, metrics.sample_rate
    );
    let [jba, jbr, jbn, jbm, jbx] = figures.jitter_buffer;
    let _ = write!(
        out,
        "JitterBuffer:JBA={jba} JBR={jbr} JBN={jbn} JBM={jbm} JBX={jbx}\r\n"
    );
    let _ = write!(
        out,
        "PacketLoss:NLR={} JDR={}\r\n",
        percent_from_256ths(figures.loss_rate),
        percent_from_256ths(figures.discard_rate)
    );
    let _ = write!(
        out,
        "BurstGapLoss:BLD={} BD={} GLD={} GD={} GMIN={}\r\n",
        percent_from_256ths(figures.burst_density),
        figures.burst_duration_ms,
        percent_from_256ths(figures.gap_density),
        figures.gap_duration_ms,
        figures.gmin
    );
    let _ = write!(
        out,
        "Delay:RTD={} ESD={}\r\n",
        figures.round_trip_delay_ms, figures.end_system_delay_ms
    );
    let (signal_level, noise_level, rerl) = figures.signal;
    let mut signal = String::from("Signal:");
    let mut wrote = false;
    if let Some(level) = signal_level {
        let _ = write!(signal, "SL={level}");
        wrote = true;
    }
    if let Some(level) = noise_level {
        push_wsp(&mut signal, &mut wrote);
        let _ = write!(signal, "NL={level}");
    }
    if let Some(rerl) = rerl {
        push_wsp(&mut signal, &mut wrote);
        let _ = write!(signal, "RERL={rerl}");
    }
    if wrote {
        out.push_str(&signal);
        out.push_str("\r\n");
    }
    let mut quality = String::from("QualityEst:");
    let mut wrote = false;
    if let Some(r) = figures.r_factor {
        let _ = write!(quality, "RCQ={r}");
        wrote = true;
    }
    // SS4.6.1's `ExternalR-In` is "measured by the local endpoint for
    // incoming connection on the 'other' side of this endpoint", which is
    // what RFC 3611 SS4.7.5's external R factor is for the end reporting it
    if let Some(r) = figures.ext_r_factor {
        push_wsp(&mut quality, &mut wrote);
        let _ = write!(quality, "EXTRI={r}");
    }
    if let Some(mos_lq) = figures.mos_lq_x10 {
        push_wsp(&mut quality, &mut wrote);
        let _ = write!(quality, "MOSLQ={}", tenths(mos_lq));
    }
    if let Some(mos_cq) = figures.mos_cq_x10 {
        push_wsp(&mut quality, &mut wrote);
        let _ = write!(quality, "MOSCQ={}", tenths(mos_cq));
    }
    if wrote {
        out.push_str(&quality);
        out.push_str("\r\n");
    }
}

fn push_wsp(out: &mut String, wrote: &mut bool) {
    if *wrote {
        out.push(' ');
    }
    *wrote = true;
}

/// RFC 6035 SS4.6.2.1: "divide by 256 and take the integer part" to turn an
/// RFC 3611 8-bit fixed-point fraction back into the percentage `NLR`,
/// `JDR`, `BLD` and `GLD` are defined in. One decimal digit, which is all
/// a value out of 256 can ever need (`256ths` is already finer than a
/// hundredth).
fn percent_from_256ths(value: u8) -> String {
    let tenths = u32::from(value) * 1000 / 256;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// A MOS field's `x10` wire units (`14..=50`) as the `D["."1*3DIGIT]` MOS
/// text RFC 6035 SS4.6.1 wants, one decimal place.
fn tenths(value_x10: u8) -> String {
    format!("{}.{}", value_x10 / 10, value_x10 % 10)
}

/// `time` as an RFC 3339 UTC timestamp, second resolution, always `Z`
/// (SS4.6.1: "Time zones other than 'Z' are not allowed"). Before the Unix
/// epoch, which no RTP stream this stack ever opens is, this reads
/// `1970-01-01T00:00:00Z` rather than propagating an error nothing here
/// could act on.
fn rfc3339(time: SystemTime) -> String {
    let secs = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs();
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let of_day = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day / 3600,
        (of_day % 3600) / 60,
        of_day % 60
    )
}

/// The proleptic Gregorian calendar date `days` days after the Unix epoch
/// (1970-01-01), correct for every day the Gregorian calendar defines in
/// either direction, including every leap year the 400/100/4-year rule
/// gives one.
///
/// This is the standard "days from/to civil" transformation: shift the
/// epoch to 1 March of year 0, which puts the extra day of a leap year at
/// the *end* of the shifted year instead of in the middle of February,
/// then read the date off by successive division through the Gregorian
/// cycle lengths — 146097 days to a 400-year cycle, 36524 to a (non-leap)
/// century, 1460 to a four-year cycle, 365 to a common year — and shift
/// the month numbering back so the result names March as month 3 again.
/// The identity is calendar mathematics, not one implementation's code, and
/// is reproduced here from its own derivation rather than copied from any.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    // 1970-01-01 is 719468 days after 0000-03-01 in the shifted calendar.
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    // days since the start of this 400-year era, 0..=146096
    let day_of_era = z.rem_euclid(146_097);
    // year within the era, 0..=399, read off the century/four-year/year
    // cycle lengths in the shifted (March-first) calendar
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    // day within the shifted year, 0..=365
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // month within the shifted year, 0 = March .. 11 = January/February
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * shifted_month + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    })
    .unwrap_or(1);
    // January and February belong to the calendar year after the one the
    // shifted (March-first) year names
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::{
        CallIdentity, Direction, QualityReportMetrics, RemoteQualityMetrics, body, civil_from_days,
        parties, percent_from_256ths, rfc3339, tenths,
    };
    use crate::UserAgent;
    use crate::account::Account;
    use crate::call::CallHandle;
    use sipral_core::endpoint::EndpointConfig;
    use sipral_core::msg::Uri;
    use std::net::SocketAddr;
    use std::time::{Duration, Instant, SystemTime};

    fn metrics() -> QualityReportMetrics {
        QualityReportMetrics {
            local_addr: "192.0.2.1:5000".parse::<SocketAddr>().expect("addr"),
            local_ssrc: 0x1a3b_5c7d,
            remote_addr: "198.51.100.9:5002".parse::<SocketAddr>().expect("addr"),
            remote_ssrc: 0x2468_abcd,
            start: SystemTime::UNIX_EPOCH + Duration::from_secs(1_128_968_623),
            stop: SystemTime::UNIX_EPOCH + Duration::from_secs(1_128_968_762),
            payload_type: 0,
            payload_desc: "PCMU",
            sample_rate: 8_000,
            loss_rate: 13,
            discard_rate: 5,
            burst_density: 0,
            burst_duration_ms: 0,
            gap_density: 5,
            gap_duration_ms: 500,
            gmin: 16,
            round_trip_delay_ms: 200,
            end_system_delay_ms: 140,
            jitter_buffer_adaptive: 3,
            jitter_buffer_rate: 2,
            jitter_buffer_nominal_ms: 40,
            jitter_buffer_maximum_ms: 80,
            jitter_buffer_abs_max_ms: 120,
            r_factor: Some(85),
            mos_lq_x10: Some(41),
            mos_cq_x10: Some(40),
            remote: None,
        }
    }

    /// RFC 6035 SS4.7.1's worked example's own `RemoteMetrics` figures, as
    /// the far end's RTCP XR VoIP Metrics block would carry them.
    fn far_end() -> RemoteQualityMetrics {
        RemoteQualityMetrics {
            loss_rate: 12,
            discard_rate: 5,
            burst_density: 0,
            burst_duration_ms: 0,
            gap_density: 5,
            gap_duration_ms: 500,
            gmin: 16,
            round_trip_delay_ms: 200,
            end_system_delay_ms: 140,
            signal_level_dbm0: Some(-21),
            noise_level_dbm0: Some(-45),
            rerl_db: Some(55),
            jitter_buffer_adaptive: 3,
            jitter_buffer_rate: 2,
            jitter_buffer_nominal_ms: 40,
            jitter_buffer_maximum_ms: 80,
            jitter_buffer_abs_max_ms: 120,
            r_factor: Some(85),
            ext_r_factor: Some(90),
            mos_lq_x10: Some(43),
            mos_cq_x10: Some(42),
        }
    }

    fn identity() -> CallIdentity {
        CallIdentity {
            from_uri: Box::from(&b"sip:alice@example.org"[..]),
            from_display: Box::from(&b"Alice"[..]),
            to_uri: Box::from(&b"sip:bill@example.net"[..]),
            call_id: Box::from(&b"6dg37f1890463"[..]),
            caller: crate::CallerIdentity::default(),
            answering: crate::Answering::default(),
        }
    }

    fn account() -> Account {
        Account::new(
            Uri::parse_str("sip:alice@example.org").expect("aor"),
            Uri::parse_str("sip:registrar.example.org").expect("registrar"),
            Uri::parse_str("sip:alice@203.0.113.1:5060").expect("contact"),
            sipral_core::endpoint::TransportId(0),
            "203.0.113.9:5060".parse().expect("remote"),
        )
    }

    #[test]
    fn the_epoch_itself_reads_as_the_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn a_known_leap_day_reads_back_correctly() {
        // 2004-02-29: 2004 is divisible by 4 and not by 100, so it is a
        // Gregorian leap year, and this is the extra day in it.
        let days = days_for(2004, 2, 29);
        assert_eq!(civil_from_days(days), (2004, 2, 29));
    }

    #[test]
    fn a_century_that_is_not_a_leap_year_has_no_february_29th() {
        // 1900 is divisible by 100 but not 400, so the 400-year rule takes
        // the leap day away again: 31 January days plus 28 February ones
        // (offsets 0..=58) reach the 59th offset, day index 59, at March
        // 1st rather than a February 29th that year never has.
        assert_eq!(civil_from_days(days_for(1900, 1, 1) + 59), (1900, 3, 1));
    }

    #[test]
    fn a_date_before_the_epoch_reads_back_too() {
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    /// The day count [`civil_from_days`] would need to read back `(y, m,
    /// d)`, found by searching outward from the epoch until it agrees --
    /// deliberately not the arithmetic the function itself uses, so the
    /// test cannot share its bug.
    fn days_for(y: i64, m: u32, d: u32) -> i64 {
        for days in -60_000_i64..60_000 {
            if civil_from_days(days) == (y, m, d) {
                return days;
            }
        }
        panic!("no day within +/- 60000 of the epoch reads back as {y}-{m}-{d}");
    }

    #[test]
    fn a_256th_reproduces_the_rfc_6035_worked_examples_percentage() {
        // RFC 6035 SS4.6.2.1's own reversal: divide by 256, take the
        // integer part; 256 * 5 / 100 = 12.8 -> 12 is the RFC 3611 field a
        // report of "5.0" (SS4.7.1's own worked example) would have come
        // from converting.
        assert_eq!(percent_from_256ths(12), "4.6");
        assert_eq!(percent_from_256ths(0), "0.0");
        assert_eq!(percent_from_256ths(255), "99.6");
    }

    #[test]
    fn a_mos_field_prints_one_decimal_place() {
        assert_eq!(tenths(41), "4.1");
        assert_eq!(tenths(10), "1.0");
    }

    #[test]
    fn an_rfc3339_timestamp_matches_a_known_instant() {
        // 2005-10-10T18:23:43Z, read off https://www.epochconverter.com and
        // matching the SS4.7.1 worked example's own date, one year later.
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(1_128_968_623);
        assert_eq!(rfc3339(time), "2005-10-10T18:23:43Z");
    }

    #[test]
    fn parties_swap_with_direction() {
        let identity = identity();
        let (local, remote) = parties(&identity, Direction::Outgoing);
        assert_eq!(local, identity.from_uri.as_ref());
        assert_eq!(remote, identity.to_uri.as_ref());

        let (local, remote) = parties(&identity, Direction::Incoming);
        assert_eq!(local, identity.to_uri.as_ref());
        assert_eq!(remote, identity.from_uri.as_ref());
    }

    #[test]
    fn the_body_carries_every_mandatory_line_and_the_metrics_given() {
        let text = String::from_utf8(body(&identity(), Direction::Outgoing, &metrics()))
            .expect("the body is ASCII");
        assert!(text.starts_with("VQSessionReport: CallTerm\r\n"));
        assert!(text.contains("CallID: 6dg37f1890463\r\n"));
        assert!(text.contains("LocalID: sip:alice@example.org\r\n"));
        assert!(text.contains("RemoteID: sip:bill@example.net\r\n"));
        assert!(text.contains("OrigID: sip:alice@example.org\r\n"));
        assert!(text.contains("LocalAddr: IP=192.0.2.1 PORT=5000 SSRC=0x1a3b5c7d\r\n"));
        assert!(text.contains("RemoteAddr: IP=198.51.100.9 PORT=5002 SSRC=0x2468abcd\r\n"));
        assert!(text.contains("LocalMetrics:\r\n"));
        assert!(
            text.contains("Timestamps:START=2005-10-10T18:23:43Z STOP=2005-10-10T18:26:02Z\r\n")
        );
        assert!(text.contains("SessionDesc:PT=0 PD=PCMU SR=8000\r\n"));
        assert!(text.contains("JitterBuffer:JBA=3 JBR=2 JBN=40 JBM=80 JBX=120\r\n"));
        assert!(text.contains("PacketLoss:NLR=5.0 JDR=1.9\r\n"));
        assert!(text.contains("BurstGapLoss:BLD=0.0 BD=0 GLD=1.9 GD=500 GMIN=16\r\n"));
        assert!(text.contains("Delay:RTD=200 ESD=140\r\n"));
        assert!(text.contains("QualityEst:RCQ=85 MOSLQ=4.1 MOSCQ=4.0\r\n"));
    }

    #[test]
    fn a_call_the_far_end_reported_on_carries_its_remote_metrics() {
        let mut reported = metrics();
        reported.remote = Some(far_end());
        let text = String::from_utf8(body(&identity(), Direction::Outgoing, &reported))
            .expect("the body is ASCII");
        let (local, remote) = text
            .split_once("RemoteMetrics:\r\n")
            .expect("a RemoteMetrics set after the local one");
        assert!(local.contains("LocalMetrics:\r\n"));
        assert!(!local.contains("Signal:"), "this end measures no signal");
        assert_eq!(
            remote,
            "Timestamps:START=2005-10-10T18:23:43Z STOP=2005-10-10T18:26:02Z\r\n\
             SessionDesc:PT=0 PD=PCMU SR=8000\r\n\
             JitterBuffer:JBA=3 JBR=2 JBN=40 JBM=80 JBX=120\r\n\
             PacketLoss:NLR=4.6 JDR=1.9\r\n\
             BurstGapLoss:BLD=0.0 BD=0 GLD=1.9 GD=500 GMIN=16\r\n\
             Delay:RTD=200 ESD=140\r\n\
             Signal:SL=-21 NL=-45 RERL=55\r\n\
             QualityEst:RCQ=85 EXTRI=90 MOSLQ=4.3 MOSCQ=4.2\r\n"
        );
    }

    #[test]
    fn a_call_the_far_end_never_reported_on_has_no_remote_metrics() {
        let text = String::from_utf8(body(&identity(), Direction::Outgoing, &metrics()))
            .expect("the body is ASCII");
        assert!(!text.contains("RemoteMetrics"));

        // and a far end that measured no signal says nothing about one
        let mut quiet = far_end();
        quiet.signal_level_dbm0 = None;
        quiet.noise_level_dbm0 = None;
        quiet.rerl_db = None;
        let mut reported = metrics();
        reported.remote = Some(quiet);
        let text = String::from_utf8(body(&identity(), Direction::Outgoing, &reported))
            .expect("the body is ASCII");
        assert!(text.contains("RemoteMetrics:\r\n"));
        assert!(!text.contains("Signal:"));
    }

    #[test]
    fn an_unavailable_e_model_report_writes_no_quality_est_line_at_all() {
        let mut without_quality = metrics();
        without_quality.r_factor = None;
        without_quality.mos_lq_x10 = None;
        without_quality.mos_cq_x10 = None;
        let text = String::from_utf8(body(&identity(), Direction::Outgoing, &without_quality))
            .expect("the body is ASCII");
        assert!(!text.contains("QualityEst"));
    }

    #[test]
    fn a_call_nobody_knows_sends_nothing_and_is_not_an_error() {
        let mut agent = UserAgent::new(EndpointConfig::default(), [7; 32]).expect("an agent");
        let sent = agent
            .send_quality_report(CallHandle(0), &metrics(), Instant::now())
            .expect("a call this agent never heard of is a no-op, not a refusal");
        assert!(!sent);
    }

    #[test]
    fn an_account_that_asked_for_no_collector_is_also_a_no_op() {
        // `account()` above never calls `quality_report_uri`, so an
        // account built from it is exactly this case: known, but silent
        // by default about where a report would go.
        assert!(account().quality_report().is_none());
    }
}
