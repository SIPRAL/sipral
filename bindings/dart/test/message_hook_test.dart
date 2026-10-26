// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The message hook: a header added to an INVITE on its way out, a response
// stopped on its way in, and a hook that throws. A loopback PBX on UDP
// answers every INVITE 486 and writes down what it received.

import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

String? header(String name, String message) {
  for (final line in message.split('\r\n')) {
    final colon = line.indexOf(':');
    if (colon > 0 &&
        line.substring(0, colon).trim().toLowerCase() == name.toLowerCase()) {
      return line.substring(colon + 1).trim();
    }
  }
  return null;
}

Uint8List withHeader(Uint8List message, String line) {
  final text = utf8.decode(message);
  final end = text.indexOf('\r\n\r\n');
  return utf8.encode(
    '${text.substring(0, end)}\r\n$line${text.substring(end)}',
  );
}

class Pbx {
  Pbx._(this._socket) {
    _socket.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = _socket.receive();
      if (datagram == null) {
        return;
      }
      final text = utf8.decode(datagram.data, allowMalformed: true);
      received.add(text);
      if (!text.startsWith('INVITE ')) {
        return;
      }
      final lines = ['SIP/2.0 486 Busy Here'];
      for (final name in ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
        var value = header(name, text);
        if (name == 'To' && value != null && !value.contains(';tag=')) {
          value = '$value;tag=pbx';
        }
        lines.add('$name: $value');
      }
      final answer = '${lines.join('\r\n')}\r\nContent-Length: 0\r\n\r\n';
      _socket.send(utf8.encode(answer), datagram.address, datagram.port);
    });
  }

  static Future<Pbx> open() async =>
      Pbx._(await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0));

  final RawDatagramSocket _socket;
  final List<String> received = [];

  String get address => '127.0.0.1:${_socket.port}';

  List<String> get invites =>
      received.where((message) => message.startsWith('INVITE ')).toList();

  void close() => _socket.close();
}

void main() {
  late Pbx pbx;
  late SipralStack stack;

  setUp(() async {
    pbx = await Pbx.open();
    stack = await SipralStack.open();
  });

  tearDown(() async {
    await stack.close();
    pbx.close();
  });

  Future<SipralStackEvent> ended() => stack.events.firstWhere(
    (event) => event.kind == SipralEventKind.callEnded,
  );

  Future<void> place() async {
    final account = stack.addAccount(
      'sip:alice@example.com',
      registrarAddress: pbx.address,
    );
    await stack.placeCall(account, 'sip:bob@example.com');
  }

  test('a header added to an outgoing INVITE reaches the PBX', () async {
    final remotes = <String>[];
    stack.setMessageHook((outgoing, message, remote) {
      remotes.add(remote);
      return outgoing && utf8.decode(message).startsWith('INVITE ')
          ? SipralMessageVerdict.replace(withHeader(message, 'X-Tenant: blue'))
          : SipralMessageVerdict.keep;
    });
    final end = ended();
    await place();
    final event = await end.timeout(const Duration(seconds: 8));
    expect(event.statusCode, 486);
    expect(pbx.invites, hasLength(1));
    expect(header('X-Tenant', pbx.invites.single), 'blue');
    expect(remotes, everyElement(pbx.address));
  });

  test('an incoming response the hook drops is not read', () async {
    var dropped = 0;
    stack.setMessageHook((outgoing, message, remote) {
      if (!outgoing && utf8.decode(message).startsWith('SIP/2.0 486')) {
        dropped += 1;
        return SipralMessageVerdict.drop;
      }
      return SipralMessageVerdict.keep;
    });
    var over = false;
    final end = ended().then((event) {
      over = true;
      return event;
    });
    await place();
    await Future<void>.delayed(const Duration(milliseconds: 1500));
    expect(over, isFalse);
    expect(dropped, greaterThan(0));

    stack.setMessageHook(null);
    final event = await end.timeout(const Duration(seconds: 8));
    expect(event.statusCode, 486);
  });

  test('a hook that throws keeps the message', () async {
    stack.setMessageHook(
      (outgoing, message, remote) =>
          throw StateError("a mistake in the application's hook"),
    );
    final end = ended();
    await place();
    final event = await end.timeout(const Duration(seconds: 8));
    expect(event.statusCode, 486);
    expect(pbx.invites, hasLength(1));
  });
}
