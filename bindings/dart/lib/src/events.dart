// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
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

/// The kinds whose payload is the locate arm.
const Set<int> _locateArm = {
  SipralEventKind.lookupWanted,
  SipralEventKind.located,
  SipralEventKind.locateFailed,
};

/// The kinds whose payload is the subscription arm.
const Set<int> _subscriptionArm = {
  SipralEventKind.subscriptionChanged,
  SipralEventKind.notified,
};

/// The kinds whose payload is the transfer arm.
const Set<int> _transferArm = {
  SipralEventKind.transferRequested,
  SipralEventKind.transferProgress,
  SipralEventKind.transferDone,
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
    this.registrationFailure,
    this.lookupRecord,
    this.lookupName,
    this.locatedTargets,
    this.locateFailure,
    this.retryInMs,
    this.subscription,
    this.subscriptionState,
    this.subscriptionStatusCode,
    this.transferStatusCode,
    this.statistics,
    this.challengeRefusal,
    this.challengeServer,
    this.challengeRealms,
  });

  factory SipralStackEvent._read(SipralEvent event) {
    final kind = event.kind;
    final call = _callArm.contains(kind);
    final digit =
        kind == SipralEventKind.digitReceived ? event.payload.media.digit : 0;
    final locating = _locateArm.contains(kind);
    final locate = locating ? event.payload.locate : null;
    final told =
        _subscriptionArm.contains(kind) ? event.payload.subscription : null;
    final transfer =
        _transferArm.contains(kind) ? event.payload.transfer : null;
    final challenge =
        kind == SipralEventKind.challengeDeclined
            ? event.payload.challenge
            : null;
    final record =
        kind == SipralEventKind.mediaStatistics
            ? event.payload.media.statistics
            : ffi.nullptr;
    String? text(ffi.Pointer<ffi.Char> data, int length) =>
        data == ffi.nullptr ? null : _decode(data.cast(), length);
    return SipralStackEvent._(
      kind,
      event.account,
      event.call,
      callState: call ? event.payload.call.state : null,
      statusCode: call ? event.payload.call.statusCode : null,
      registrationState:
          kind == SipralEventKind.registrationChanged
              ? event.payload.registration.state
              : null,
      digit: digit > 0 ? String.fromCharCode(digit) : null,
      registrationFailure:
          kind == SipralEventKind.registrationChanged
              ? event.payload.registration.failure
              : null,
      lookupRecord: locate?.record,
      lookupName: locate == null ? null : text(locate.name, locate.nameLen),
      locatedTargets:
          locate == null ? null : text(locate.targets, locate.targetsLen),
      locateFailure: locate?.failure,
      retryInMs: locate?.retryInMs,
      subscription: told?.subscription,
      subscriptionState: told?.state,
      subscriptionStatusCode: told?.statusCode,
      transferStatusCode: transfer?.statusCode,
      challengeRefusal: challenge?.refusal,
      challengeServer:
          challenge == null
              ? null
              : text(challenge.server, challenge.serverLen),
      challengeRealms:
          challenge == null
              ? null
              : (text(challenge.realms, challenge.realmsLen) ?? '')
                  .split('\n')
                  .where((realm) => realm.isNotEmpty)
                  .toList(),
      statistics:
          record == ffi.nullptr ? null : SipralMediaStatistics._(record.ref),
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

  /// Why an account's password was not given to a challenge, a
  /// `SipralChallengeRefusal` value, for `SipralEventKind.challengeDeclined`.
  final int? challengeRefusal;

  /// Where the challenged request went, `host:port`, for
  /// `SipralEventKind.challengeDeclined`.
  final String? challengeServer;

  /// The realms it was challenged for, for
  /// `SipralEventKind.challengeDeclined`.
  final List<String>? challengeRealms;

  /// The account's `SipralRegistrationState` value, for
  /// `SipralEventKind.registrationChanged`.
  final int? registrationState;

  /// The digit, for `SipralEventKind.digitReceived`.
  final String? digit;

  /// Why a registration failed, a `SipralRegistrationFailure` value --
  /// `unreachableContact` for a `Contact` the registrar cannot reach -- for
  /// `SipralEventKind.registrationChanged`.
  final int? registrationFailure;

  /// What to ask [lookupName] for, a `SipralDnsRecordType` value, for
  /// `SipralEventKind.lookupWanted`.
  final int? lookupRecord;

  /// The name a lookup asks, for `SipralEventKind.lookupWanted`.
  final String? lookupName;

  /// Every address the account's server was located at, `host:port`
  /// separated by commas, the one in use first, for
  /// `SipralEventKind.located`.
  final String? locatedTargets;

  /// Why a server was not located, a `SipralLocateFailure` value, for
  /// `SipralEventKind.locateFailed`.
  final int? locateFailure;

  /// When the name is looked up again after a failure, in milliseconds.
  final int? retryInMs;

  /// Which subscription moved or was notified, for
  /// `SipralEventKind.subscriptionChanged` and `SipralEventKind.notified`.
  final int? subscription;

  /// Where that subscription is now, a `sipral_subscription_state_t` value.
  final int? subscriptionState;

  /// The SIP status behind the subscription's move, or zero.
  final int? subscriptionStatusCode;

  /// The status code the transfer's target answered with, for the three
  /// transfer kinds: what the far end's `message/sipfrag` NOTIFY said, or
  /// zero before it said anything.
  final int? transferStatusCode;

  /// What the call's media cost in the end, for
  /// `SipralEventKind.mediaStatistics`: the record the library hands over
  /// once the stream is gone, copied while the callback still owns it.
  final SipralMediaStatistics? statistics;

  @override
  String toString() =>
      'SipralStackEvent(kind: $kind, account: $account, call: $call)';
}
