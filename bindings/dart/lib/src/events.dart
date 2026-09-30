// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// One event, copied out of the `sipral_event_t` the callback was handed,
// which is the library's only for the length of the callback.

part of 'idiomatic.dart';

/// The kinds whose payload is the call arm (`EVENT_KIND_ARMS` in
/// crates/sipral-ffi/src/event.rs): what [SipralStackEvent.callState] and
/// [SipralStackEvent.statusCode] are read from.
const Set<int> _callArm = {
  SipralEventKind.started,
  SipralEventKind.incomingCall,
  SipralEventKind.callProgress,
  SipralEventKind.callForked,
  SipralEventKind.callConfirmed,
  SipralEventKind.sessionChanged,
  SipralEventKind.sessionOffered,
  SipralEventKind.sessionChangeFailed,
  SipralEventKind.callReplaced,
  SipralEventKind.callEnded,
  SipralEventKind.dtmfSent,
};

/// Something a stack reports, with the part of its payload this layer reads.
///
/// Every union arm the event did not write is left unread: its bytes are
/// another arm's, and mean nothing as this one.
final class SipralStackEvent {
  SipralStackEvent._(
    this.kind,
    this.account,
    this.call, {
    this.callState,
    this.statusCode,
    this.registrationState,
    this.digit,
  });

  factory SipralStackEvent._read(SipralEvent event) {
    final kind = event.kind;
    final call = _callArm.contains(kind);
    final digit =
        kind == SipralEventKind.digitReceived ? event.payload.media.digit : 0;
    return SipralStackEvent._(
      kind,
      event.account,
      event.call,
      callState: call ? event.payload.call.state : null,
      statusCode: call ? event.payload.call.statusCode : null,
      registrationState: kind == SipralEventKind.registrationChanged
          ? event.payload.registration.state
          : null,
      digit: digit > 0 ? String.fromCharCode(digit) : null,
    );
  }

  /// A `SipralEventKind` value.
  final int kind;

  /// The account it is about, or zero.
  final int account;

  /// The call it is about, or zero.
  final int call;

  /// The call's `SipralCallState` value, for an event about a call.
  final int? callState;

  /// The SIP status code behind it, for an event about a call, or zero.
  final int? statusCode;

  /// The account's `SipralRegistrationState` value, for
  /// `SipralEventKind.registrationChanged`.
  final int? registrationState;

  /// The digit, for `SipralEventKind.digitReceived`.
  final String? digit;

  @override
  String toString() =>
      'SipralStackEvent(kind: $kind, account: $account, call: $call)';
}
