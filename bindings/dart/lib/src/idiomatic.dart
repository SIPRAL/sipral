// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The idiomatic Dart layer over `sipral_abi.dart`, which tools/abi-gen
// prints and nothing here edits: a stack with its signalling socket, an
// account, a call with its media, and the stack's events as a Stream. It is
// built over the same six calls the other idiomatic layers are -- create,
// poll, the two receive entry points, poll_transmit and destroy -- and runs
// on the isolate that opened the stack: sockets are `RawDatagramSocket`s,
// the poll and each call's frame clock are timers, and the event callback
// is a `NativeCallable.isolateLocal`, which the library calls from inside
// `sipral_stack_poll` on this same thread (`docs/08-ffi.md`). Nothing is
// ever called from two threads, so `SIPRAL_STATUS_BUSY` does not arise.
//
// The application runs each call's audio: `SipralMedia.frames` is the far
// end's PCM, `SipralMedia.sendAudio` takes this end's, and silence goes out
// when nothing was given, so RTP flows from the moment media starts.

import 'dart:async';
import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'sipral_abi.dart';

part 'account.dart';
part 'call.dart';
part 'events.dart';
part 'locate.dart';
part 'media.dart';
part 'settings.dart';
part 'stack.dart';

/// The largest datagram a socket here reads or a packet here is written into.
const int _packetBytes = 65536;

/// Room for one `host:port`, as the library writes it.
const int _addressBytes = 128;

/// The first transport number a connection this layer opens is bound at,
/// one more for each after it: clear of `Sipral.transportMain` and of the
/// small numbers an application driving the library itself would pick.
const int _firstStream = 64;

Sipral? _shared;

/// The library [SipralStack.open] uses when it is given none: opened, and
/// its ABI checked, the first time a stack needs it.
Sipral _library() => _shared ??= Sipral.open();

/// A call into the library that did not return `SIPRAL_STATUS_OK`.
final class SipralException implements Exception {
  SipralException(this.status, this.operation, this.detail);

  /// The `SipralStatus` value it returned.
  final int status;

  /// The entry point, as the header names it.
  final String operation;

  /// What the library said about it, from `sipral_last_error_message`.
  final String detail;

  @override
  String toString() => 'sipral: $operation returned $status: $detail';
}

/// Throw [SipralException] unless [status] is `SIPRAL_STATUS_OK`, with the
/// library's own words for it.
void _check(Sipral sipral, String operation, int status) {
  if (status == SipralStatus.ok) {
    return;
  }
  final detail = using((arena) {
    final buffer = arena<ffi.Char>(1024);
    final length = arena<ffi.Size>();
    if (sipral.lastErrorMessage(buffer, 1024, length) != SipralStatus.ok) {
      return '';
    }
    // the length counts the trailing NUL, which is not part of the message
    return _decode(buffer.cast(), max(0, min(length.value, 1024) - 1));
  });
  throw SipralException(status, operation, detail);
}

/// The status [entryPoint] returns, called again while that is
/// `SipralStatus.clockBehind` -- for up to half a second -- the way the .NET
/// layer waits it out: every [entryPoint] here reads `nowMs()` afresh right
/// before the call, so a reading the stack's last one beat can only be
/// followed by a later one. Not part of the package's surface; public only
/// so that its test can reach it.
int retryingClockBehind(int Function() entryPoint) {
  final waited = Stopwatch()..start();
  var status = entryPoint();
  while (status == SipralStatus.clockBehind &&
      waited.elapsedMilliseconds < 500) {
    sleep(const Duration(milliseconds: 1));
    status = entryPoint();
  }
  return status;
}

/// [_check] over what [retryingClockBehind] makes of [entryPoint].
void _checkNow(Sipral sipral, String operation, int Function() entryPoint) =>
    _check(sipral, operation, retryingClockBehind(entryPoint));

/// The prefixes a certificate fingerprint may come after, lower case.
const List<String> _pinPrefixes = [
  'sha256 fingerprint=',
  'sha-256 ',
  'sha256=',
];

/// The 32 bytes a SHA-256 certificate fingerprint names, as `openssl x509
/// -fingerprint -sha256` (`sha256 Fingerprint=`, or `SHA256 Fingerprint=`
/// before OpenSSL 3) or RFC 8122 prints it: 64 hexadecimal digits, either
/// case, colons and spaces between them ignored, optionally after
/// `sha-256 `, `SHA256=` or `SHA256 Fingerprint=`, in any case. Anything else
/// throws [ArgumentError]; `bindings/fixtures/pin-forms.txt` lists what every
/// layer takes. [SipralStack.addAccount]'s `tlsPin` is read with it.
Uint8List sipralPinDigest(String fingerprint) {
  var text = fingerprint.trim();
  final lowered = text.toLowerCase();
  for (final prefix in _pinPrefixes) {
    if (lowered.startsWith(prefix)) {
      text = text.substring(prefix.length);
      break;
    }
  }
  final digits = text.replaceAll(':', '').replaceAll(' ', '');
  if (digits.length != 64 || !RegExp(r'^[0-9a-fA-F]+$').hasMatch(digits)) {
    throw ArgumentError.value(
      fingerprint,
      'fingerprint',
      'a certificate pin is a SHA-256 fingerprint: 64 hexadecimal digits, '
          'optionally after sha-256, SHA256= or SHA256 Fingerprint=',
    );
  }
  return Uint8List.fromList([
    for (var at = 0; at < 64; at += 2)
      int.parse(digits.substring(at, at + 2), radix: 16),
  ]);
}

/// [text] as UTF-8 in memory [arena] owns, and its length in bytes; a null
/// pointer and zero for no text.
(ffi.Pointer<ffi.Char>, int) _text(Arena arena, String? text) {
  if (text == null) {
    return (ffi.nullptr, 0);
  }
  final bytes = utf8.encode(text);
  final memory = arena<ffi.Uint8>(bytes.length + 1);
  memory.asTypedList(bytes.length).setAll(0, bytes);
  memory[bytes.length] = 0;
  return (memory.cast(), bytes.length);
}

/// [length] bytes at [data] as UTF-8.
String _decode(ffi.Pointer<ffi.Uint8> data, int length) =>
    length == 0
        ? ''
        : utf8.decode(data.asTypedList(length), allowMalformed: true);

/// `host:port`, with an IPv6 host in brackets.
String _formatAddress(InternetAddress host, int port) =>
    host.type == InternetAddressType.IPv6
        ? '[${host.address}]:$port'
        : '${host.address}:$port';

/// The host and the port of a `host:port` the library wrote, or null for
/// one whose host is not an address literal: a name is the application's
/// to resolve, and `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` asks it to.
(InternetAddress, int)? _parseAddress(String text) {
  final colon = text.lastIndexOf(':');
  if (colon <= 0) {
    return null;
  }
  var host = text.substring(0, colon);
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.substring(1, host.length - 1);
  }
  final address = InternetAddress.tryParse(host);
  final port = int.tryParse(text.substring(colon + 1));
  if (address == null || port == null) {
    return null;
  }
  return (address, port);
}

/// Report [error] where an uncaught one goes, without letting it unwind
/// into the library that called back into Dart.
void _report(Object error, StackTrace trace) {
  Zone.current.handleUncaughtError(error, trace);
}
