// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// What a stack runs with, `sipral_stack_settings_t` read back.

part of 'idiomatic.dart';

/// What a stack runs with, every default filled in
/// ([SipralStack.settings]): what a settings screen or a support report
/// shows, rather than what was passed. Every toggle is read as a `bool`;
/// [rtpPorts] is null for no range, [mediaStallMs] and
/// [registrarKeepaliveMs] zero with that watchdog or keep-alive off.
final class SipralSettings {
  SipralSettings._(SipralStackSettings raw, this.srtpSuites)
    : transport = raw.transport,
      retransmits = raw.retransmits != 0,
      timerT1Ms = raw.timerT1Ms,
      timerT2Ms = raw.timerT2Ms,
      timerT4Ms = raw.timerT4Ms,
      codecCount = raw.codecCount,
      frameMs = raw.frameMs,
      offerDtmf = raw.offerDtmf == SipralToggle.on,
      offerRtcpMux = raw.offerRtcpMux == SipralToggle.on,
      silenceSuppression = raw.silenceSuppression == SipralToggle.on,
      mediaStallMs = raw.mediaStallMs,
      g729AnnexB = raw.g729AnnexB == SipralToggle.on,
      referrals = raw.referrals == SipralToggle.on,
      registrarKeepaliveMs = raw.registrarKeepaliveMs,
      maxDialogs = raw.maxDialogs,
      maxServerTransactions = raw.maxServerTransactions,
      diagnosticDecisions = raw.diagnosticDecisions,
      diagnosticRecords = raw.diagnosticRecords,
      rtpPorts =
          raw.rtpPortMin == 0 && raw.rtpPortMax == 0
              ? null
              : (raw.rtpPortMin, raw.rtpPortMax),
      pathMtu = raw.pathMtu,
      datagramWithoutStreamBytes = raw.datagramWithoutStreamBytes,
      pseudonymSalted = raw.pseudonymSalted == SipralToggle.on,
      diagnosticTrace = raw.diagnosticTrace == SipralToggle.on,
      systemEchoCancellation = raw.systemEchoCancellation == SipralToggle.on;

  /// The `SipralTransport` value the stack signals over.
  final int transport;

  /// Whether it retransmits anything itself: only over UDP.
  final bool retransmits;
  final int timerT1Ms;
  final int timerT2Ms;
  final int timerT4Ms;

  /// How many codecs the stack offers.
  final int codecCount;
  final int frameMs;
  final bool offerDtmf;
  final bool offerRtcpMux;
  final bool silenceSuppression;
  final int mediaStallMs;
  final bool g729AnnexB;
  final bool referrals;
  final int registrarKeepaliveMs;
  final int maxDialogs;
  final int maxServerTransactions;
  final int diagnosticDecisions;
  final int diagnosticRecords;
  final (int, int)? rtpPorts;
  final int pathMtu;
  final int datagramWithoutStreamBytes;

  /// The SRTP suites the stack's calls offer and accept unless their account
  /// names its own, in the order they are offered, as `SipralSrtpSuite`
  /// values (ABI 0.35).
  final List<int> srtpSuites;

  /// Whether a `pseudonymSalt` was given; the salt itself is never read back
  /// (ABI 0.35).
  final bool pseudonymSalted;

  /// Whether the trace writes whole messages now (ABI 0.35).
  final bool diagnosticTrace;

  /// Whether the platform's echo cancellation is asked for, the default
  /// filled in (ABI 0.35). This layer runs every call's audio in the
  /// application, where the library opens no device.
  final bool systemEchoCancellation;
}
