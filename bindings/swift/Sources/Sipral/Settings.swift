// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek

import CSipral

/// The effective settings, defaults filled in (`SipralStack.settings()`).
public struct SipralSettings: Sendable, Equatable {
    /// The protocol the stack signals over.
    public let transport: SipralTransport?
    /// Whether it retransmits anything itself: only over UDP.
    public let retransmits: Bool
    public let timerT1Ms: UInt64
    public let timerT2Ms: UInt64
    public let timerT4Ms: UInt64
    /// How many codecs the stack offers.
    public let codecCount: Int
    public let frameMs: UInt32
    public let offerDtmf: Bool
    public let offerRtcpMux: Bool
    public let silenceSuppression: Bool
    /// How long inbound audio may stop before it is reported; zero with the
    /// watchdog off.
    public let mediaStallMs: UInt64
    public let g729AnnexB: Bool
    public let referrals: Bool
    /// How often an account behind a NAT sends to its registrar; zero when
    /// that keep-alive is off.
    public let registrarKeepaliveMs: UInt64
    public let maxDialogs: UInt32
    public let maxServerTransactions: UInt32
    public let diagnosticDecisions: UInt32
    public let diagnosticRecords: UInt32
    /// The RTP port range as given, `nil` for none.
    public let rtpPorts: ClosedRange<UInt32>?
    /// The path MTU as given, zero for unknown.
    public let pathMtu: UInt32
    /// `datagramWithoutStreamBytes` as given, zero for never.
    public let datagramWithoutStreamBytes: UInt32
    /// The SRTP suites calls offer and accept unless their account names
    /// its own, in offer order.
    public let srtpSuites: [SipralSrtpSuite]
    /// Whether a `pseudonymSalt` was given; the salt is never read back.
    public let pseudonymSalted: Bool
    /// Whether the trace currently writes whole messages.
    public let diagnosticTrace: Bool
    /// Whether platform echo cancellation is requested;
    /// `AudioStatus.systemEchoCancellation` says what the platform did.
    public let systemEchoCancellation: Bool

    init(_ raw: sipral_stack_settings_t, srtpSuites: [SipralSrtpSuite]) {
        let on = { (value: UInt32) in value == SipralToggle.on.rawValue }
        transport = SipralTransport(rawValue: raw.transport)
        retransmits = raw.retransmits != 0
        timerT1Ms = raw.timer_t1_ms
        timerT2Ms = raw.timer_t2_ms
        timerT4Ms = raw.timer_t4_ms
        codecCount = Int(raw.codec_count)
        frameMs = raw.frame_ms
        offerDtmf = on(raw.offer_dtmf)
        offerRtcpMux = on(raw.offer_rtcp_mux)
        silenceSuppression = on(raw.silence_suppression)
        mediaStallMs = raw.media_stall_ms
        g729AnnexB = on(raw.g729_annex_b)
        referrals = on(raw.referrals)
        registrarKeepaliveMs = raw.registrar_keepalive_ms
        maxDialogs = raw.max_dialogs
        maxServerTransactions = raw.max_server_transactions
        diagnosticDecisions = raw.diagnostic_decisions
        diagnosticRecords = raw.diagnostic_records
        rtpPorts = raw.rtp_port_min == 0 && raw.rtp_port_max == 0 ? nil : raw.rtp_port_min...raw.rtp_port_max
        pathMtu = raw.path_mtu
        datagramWithoutStreamBytes = raw.datagram_without_stream_bytes
        self.srtpSuites = srtpSuites
        pseudonymSalted = on(raw.pseudonym_salted)
        diagnosticTrace = on(raw.diagnostic_trace)
        systemEchoCancellation = on(raw.system_echo_cancellation)
    }
}
