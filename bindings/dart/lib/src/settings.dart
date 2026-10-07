// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// What a stack runs with, `sipral_stack_settings_t` read back.

part of 'idiomatic.dart';

/// The settings a stack runs with, defaults filled in
/// ([SipralStack.settings]). [rtpPorts] is null for no range;
/// [mediaStallMs] and [registrarKeepaliveMs] are zero when off.
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

  /// The default SRTP suites in offer order, as `SipralSrtpSuite` values; an
  /// account may name its own.
  final List<int> srtpSuites;

  /// Whether a `pseudonymSalt` was given; the salt itself is never read back.
  final bool pseudonymSalted;

  /// Whether the trace writes whole messages.
  final bool diagnosticTrace;

  /// Whether the platform's echo cancellation is asked for. This layer opens
  /// no audio device, so the application applies it.
  final bool systemEchoCancellation;
}
