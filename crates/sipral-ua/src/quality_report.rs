// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

//! End-of-call voice quality reports (RFC 6035), sent by PUBLISH (RFC 3903)
//! rather than NOTIFY: §3 leaves the method open, and a one-shot report has
//! no subscriber, only a collector.
//!
//! One report per call, never retried: §5 already warns of a burst of
//! reports at call end, and retries would multiply it. The figures are
//! RFC 3611 VoIP Metrics, all supplied by the caller since this crate does
//! not measure RTP.
//!
//! `LocalMetrics` is always written. `RemoteMetrics` (§4.6) is what the far
//! end measured of our stream, from its last RTCP XR VoIP Metrics block
//! ([`QualityReportMetrics::remote`]); left out when none arrived, since
//! zeros would claim a measurement nobody made.

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

/// RFC 6035 §4.1.
const EVENT_PACKAGE: &[u8] = b"vq-rtcpxr";

/// RFC 6035 §4.5.
const CONTENT_TYPE: &[u8] = b"application/vq-rtcpxr";

/// Cap on [`EndedCall`] snapshots. A call never reported on (refused,
/// cancelled, no media) leaves its entry unconsumed, so the oldest is
/// evicted.
const SNAPSHOT_CAP: usize = 32;

/// What [`UserAgent::send_quality_report`] needs about a call already gone
/// from [`UserAgent::calls`]: `finish` forgets the call in the same step that
/// queues `CallEnded`, before the application can react to it.
#[derive(Clone, Debug)]
pub(crate) struct EndedCall {
    pub(crate) account: AccountId,
    pub(crate) identity: CallIdentity,
    pub(crate) direction: Direction,
}

/// The RFC 3611 VoIP Metrics figures, supplied by the caller. Plain scalars
/// so this signalling crate does not depend on `sipral-rtp`.
#[derive(Clone, Debug)]
pub struct QualityReportMetrics {
    /// Where this end's RTP arrived.
    pub local_addr: SocketAddr,
    /// Our SSRC.
    pub local_ssrc: u32,
    /// Where this end sent RTP.
    pub remote_addr: SocketAddr,
    /// The far end's SSRC.
    pub remote_ssrc: u32,
    /// When the stream started.
    pub start: SystemTime,
    /// When it ended.
    pub stop: SystemTime,
    /// The last RTP payload type in use.
    pub payload_type: u8,
    /// IANA media-type name, e.g. `"PCMU"` (RFC 6035 §4.6.1 `PayloadDesc`).
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
    /// RFC 3611 §4.7.7's current maximum jitter buffer delay, in ms.
    pub jitter_buffer_maximum_ms: u16,
    /// RFC 3611 §4.7.7's absolute maximum jitter buffer delay, in ms.
    pub jitter_buffer_abs_max_ms: u16,
    /// RFC 3611 §4.7.5's R factor, `0..=100`; `None` for "unavailable".
    pub r_factor: Option<u8>,
    /// RFC 3611 §4.7.5's MOS-LQ in tenths (`14..=50`); `None` for
    /// "unavailable".
    pub mos_lq_x10: Option<u8>,
    /// RFC 3611 §4.7.5's MOS-CQ in tenths; `None` for "unavailable".
    pub mos_cq_x10: Option<u8>,
    /// The far end's last XR VoIP Metrics block about `local_ssrc`, written
    /// as `RemoteMetrics`. `None` leaves that set out.
    pub remote: Option<RemoteQualityMetrics>,
}

/// The far end's RFC 3611 §4.7 VoIP Metrics block about our stream. Span
/// and codec come from [`QualityReportMetrics`].
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
    /// RFC 3611 §4.7.3's round-trip delay, in ms, as the far end saw it.
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
    /// RFC 3611 §4.7.7's current maximum jitter buffer delay, in ms.
    pub jitter_buffer_maximum_ms: u16,
    /// RFC 3611 §4.7.7's absolute maximum jitter buffer delay, in ms.
    pub jitter_buffer_abs_max_ms: u16,
    /// RFC 3611 §4.7.5's R factor, or `None` for "unavailable".
    pub r_factor: Option<u8>,
    /// RFC 3611 SS4.7.5's external R factor, or `None`.
    pub ext_r_factor: Option<u8>,
    /// RFC 3611 SS4.7.5's MOS-LQ, in tenths, or `None`.
    pub mos_lq_x10: Option<u8>,
    /// RFC 3611 SS4.7.5's MOS-CQ, in tenths, or `None`.
    pub mos_cq_x10: Option<u8>,
}

/// One `Metrics` set (§4.6.1), from either end.
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
            // nobody measures these for this end
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
    /// `Ok(false)` when there is nothing to do: unknown call, no account, or
    /// no collector. `Ok(true)` once the PUBLISH went out, with
    /// `Expires: 0` (RFC 3903 §3) since nothing will refresh it. Its answer
    /// is not reported and nothing is retried.
    ///
    /// # Errors
    /// Whatever [`sipral_core::endpoint::Endpoint::request`] refuses the
    /// PUBLISH for, most likely a transport no longer bound.
    pub fn send_quality_report(
        &mut self,
        call: CallHandle,
        metrics: &QualityReportMetrics,
        now: Instant,
    ) -> Result<bool, UaError> {
        // usually the call is already gone and only the snapshot is left;
        // a live call is read first so it is never stale
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

    /// Called from `finish` just before the call is forgotten. Only for
    /// accounts with a collector
    /// ([`Account::quality_report`](crate::account::Account::quality_report)),
    /// bounded by [`SNAPSHOT_CAP`].
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

/// (local, remote) for `LocalID`/`RemoteID`. [`CallIdentity`] holds the
/// opening request's `From`/`To`, so which is ours depends on direction.
fn parties(identity: &CallIdentity, direction: Direction) -> (&[u8], &[u8]) {
    match direction {
        Direction::Outgoing => (&identity.from_uri, &identity.to_uri),
        Direction::Incoming => (&identity.to_uri, &identity.from_uri),
    }
}

/// The RFC 6035 §4.6.1 `VQSessionReport: CallTerm` body.
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
    // OrigID is the originator: the opening request's `From`
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
        // same session span and codec as ours
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

/// `LocalAddr`/`RemoteAddr` value (§4.6.1).
fn addr_line(addr: SocketAddr, ssrc: u32) -> String {
    format!("IP={} PORT={} SSRC=0x{:x}", addr.ip(), addr.port(), ssrc)
}

/// One `Metrics` block (§4.6.1), lines in §4.7.1's order. A line with no
/// value at all is left out, as §4.6 asks.
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
    // §4.6.1 `ExternalR-In` is RFC 3611 §4.7.5's external R factor
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

/// An RFC 3611 fraction in 256ths as a one-decimal percentage, for `NLR`,
/// `JDR`, `BLD` and `GLD` (RFC 6035 §4.6.2.1).
fn percent_from_256ths(value: u8) -> String {
    let tenths = u32::from(value) * 1000 / 256;
    format!("{}.{}", tenths / 10, tenths % 10)
}

/// MOS in tenths as `D.D` text (§4.6.1).
fn tenths(value_x10: u8) -> String {
    format!("{}.{}", value_x10 / 10, value_x10 % 10)
}

/// RFC 3339 UTC, whole seconds, always `Z` (§4.6.1). Pre-epoch times clamp
/// to the epoch.
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

/// Proleptic Gregorian date `days` after 1970-01-01, either direction.
///
/// Shift the epoch to 0000-03-01 so a leap day falls at the end of the
/// shifted year, then divide down through the cycle lengths (146097 days
/// per 400 years, 36524 per century, 1460 per four years, 365 per year).
/// Derived from the calendar rules, not copied.
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    // 1970-01-01 is day 719468 of the March-first calendar
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    // 0 = March .. 11 = February
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = u32::try_from(day_of_year - (153 * shifted_month + 2) / 5 + 1).unwrap_or(1);
    let month = u32::try_from(if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    })
    .unwrap_or(1);
    // January and February belong to the next calendar year
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

    /// RFC 6035 §4.7.1's example `RemoteMetrics`.
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
        let days = days_for(2004, 2, 29);
        assert_eq!(civil_from_days(days), (2004, 2, 29));
    }

    #[test]
    fn a_century_that_is_not_a_leap_year_has_no_february_29th() {
        // 31 + 28 days after 1 January is 1 March in 1900
        assert_eq!(civil_from_days(days_for(1900, 1, 1) + 59), (1900, 3, 1));
    }

    #[test]
    fn a_date_before_the_epoch_reads_back_too() {
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    /// Found by search, not by the function's own arithmetic, so the test
    /// cannot share its bug.
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
        // RFC 6035 §4.6.2.1
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
        assert!(account().quality_report().is_none());
    }
}
