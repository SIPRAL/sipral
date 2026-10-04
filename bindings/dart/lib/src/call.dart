// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// One call, its media socket, and its media once the session is up.

part of 'idiomatic.dart';

/// A call placed with [SipralStack.placeCall] or answered with
/// [SipralStack.answerCall].
final class SipralCall {
  SipralCall._(
    this.stack,
    this.handle,
    this._mediaSocket,
    this.mediaAddress, {
    required this.incoming,
  });

  /// The stack it belongs to.
  final SipralStack stack;

  /// The call's handle.
  final int handle;

  /// Whether the far end placed it.
  final bool incoming;

  /// Where its media socket is bound, `host:port`: what its SDP offers.
  final String mediaAddress;

  final RawDatagramSocket _mediaSocket;
  final Completer<void> _confirmed = Completer();
  final Completer<void> _ended = Completer();
  bool _closed = false;

  /// The call's media, from `SipralEventKind.mediaStarted` until the call
  /// is closed; null before and after.
  SipralMedia? get media => _media;
  SipralMedia? _media;

  /// Whether `SipralEventKind.callEnded` has been delivered.
  bool get ended => _ended.isCompleted;

  /// What the call's media cost in the end: the record
  /// `SipralEventKind.mediaStatistics` carries, kept from the moment it
  /// arrives -- right after `SipralEventKind.callEnded` -- and null before
  /// that or for a call whose media never started. [SipralMedia.statistics]
  /// answers with it too once the stream is gone.
  SipralMediaStatistics? get finalStatistics => _finalStatistics;
  SipralMediaStatistics? _finalStatistics;

  /// Every event about this call, in order.
  Stream<SipralStackEvent> get events =>
      stack.events.where((event) => event.call == handle);

  /// Each digit the far end sends, RFC 4733 or SIP INFO alike.
  Stream<String> get digits => events
      .where(
        (event) =>
            event.kind == SipralEventKind.digitReceived && event.digit != null,
      )
      .map((event) => event.digit!);

  /// Where the call is, a `SipralCallState` value; `terminated` once it has
  /// ended.
  int get state {
    if (ended) {
      return SipralCallState.terminated;
    }
    return using((arena) {
      final out = arena<ffi.Uint32>();
      _check(
        stack._sipral,
        'sipral_call_state',
        stack._sipral.callState(stack.handle, handle, out),
      );
      return out.value;
    });
  }

  /// Complete once the call is confirmed; complete with a [StateError] if
  /// it ends first, and with a [TimeoutException] after [timeout].
  Future<void> confirmed({Duration timeout = const Duration(seconds: 30)}) =>
      _confirmed.future.timeout(timeout);

  /// Complete once the call has ended, and with a [TimeoutException] after
  /// [timeout].
  Future<void> whenEnded({Duration timeout = const Duration(seconds: 30)}) =>
      _ended.future.timeout(timeout);

  /// Send [digits] (`0`-`9`, `*`, `#`, `A`-`D`), [via] 1 for RFC 4733
  /// events, each lasting [durationMs].
  void sendDtmf(String digits, {int via = 1, int durationMs = 100}) {
    stack._ensureOpen();
    using((arena) {
      final text = _text(arena, digits);
      _checkNow(
        stack._sipral,
        'sipral_call_send_dtmf',
        () => stack._sipral.callSendDtmf(
          stack.handle,
          handle,
          text.$1,
          text.$2,
          via,
          durationMs,
          stack.nowMs(),
        ),
      );
    });
    stack._poll();
  }

  /// Hang up: a BYE once confirmed, a CANCEL while still ringing out.
  void hangup() {
    stack._ensureOpen();
    _checkNow(
      stack._sipral,
      'sipral_call_hangup',
      () => stack._sipral.callHangup(stack.handle, handle, stack.nowMs()),
    );
    stack._poll();
  }

  /// Release the media and close the media socket. The call is forgotten by
  /// its stack; hang it up first if it is still up.
  void close() {
    if (_closed) {
      return;
    }
    _closed = true;
    _media?._close();
    _media = null;
    _mediaSocket.close();
    stack._forget(this);
  }

  void _deliver(SipralStackEvent event) {
    switch (event.kind) {
      case SipralEventKind.mediaStarted:
        if (_media == null && !_closed) {
          _media = SipralMedia._(this, _mediaSocket);
        }
      case SipralEventKind.callConfirmed:
        if (!_confirmed.isCompleted) {
          _confirmed.complete();
        }
      case SipralEventKind.mediaStatistics:
        _finalStatistics = event.statistics ?? _finalStatistics;
      case SipralEventKind.callEnded:
        if (!_confirmed.isCompleted) {
          _confirmed.completeError(
            StateError('sipral: the call ended before it was confirmed'),
          );
          // nobody may be waiting for a confirmation that never came
          _confirmed.future.ignore();
        }
        if (!_ended.isCompleted) {
          _ended.complete();
        }
    }
  }

  /// One packet out of the call's socket, where it says to go.
  void _sendPacket(_MediaPacket packet) {
    if (_closed) {
      return;
    }
    final to = _parseAddress(packet.destination());
    if (to != null) {
      _mediaSocket.send(packet.payload(), to.$1, to.$2);
    }
  }
}
