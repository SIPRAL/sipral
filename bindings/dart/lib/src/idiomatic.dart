// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The idiomatic Dart layer over the generated `sipral_abi.dart`: a stack with
// its signalling socket, accounts, calls with their media, and events as a
// Stream. Everything runs on the isolate that opened the stack. The event
// callback is a `NativeCallable.isolateLocal`, called from inside
// `sipral_stack_poll` on this same thread (`docs/08-ffi.md`), so
// `SIPRAL_STATUS_BUSY` never arises.
//
// Silence goes out when the application gave no audio, so RTP flows from the
// moment media starts.

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

/// First transport number for connections this layer opens, clear of
/// `Sipral.transportMain` and of small numbers an application might pick.
const int _firstStream = 64;

Sipral? _shared;

/// The library [SipralStack.open] uses when given none, opened on first use.
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

/// Calls [entryPoint] again while it returns `SipralStatus.clockBehind`, for
/// up to half a second. Each [entryPoint] reads `nowMs()` afresh, so a retry
/// always carries a later time. Public only so that its test can reach it.
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

void _checkNow(Sipral sipral, String operation, int Function() entryPoint) =>
    _check(sipral, operation, retryingClockBehind(entryPoint));

const List<String> _pinPrefixes = [
  'sha256 fingerprint=',
  'sha-256 ',
  'sha256=',
];

/// The 32 bytes of a SHA-256 certificate fingerprint as `openssl x509
/// -fingerprint -sha256` or RFC 8122 prints it: 64 hex digits in either case,
/// colons and spaces ignored, optionally after `sha-256 `, `SHA256=` or
/// `SHA256 Fingerprint=`. Anything else throws [ArgumentError];
/// `bindings/fixtures/pin-forms.txt` lists the accepted forms.
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

String _decode(ffi.Pointer<ffi.Uint8> data, int length) =>
    length == 0
        ? ''
        : utf8.decode(data.asTypedList(length), allowMalformed: true);

String _formatAddress(InternetAddress host, int port) =>
    host.type == InternetAddressType.IPv6
        ? '[${host.address}]:$port'
        : '${host.address}:$port';

/// Null when the host is a name: `SIPRAL_EVENT_KIND_RESOLVE_NEEDED` asks the
/// application to resolve those.
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

/// Reports [error] without letting it unwind into the library that called
/// back into Dart.
void _report(Object error, StackTrace trace) {
  Zone.current.handleUncaughtError(error, trace);
}
