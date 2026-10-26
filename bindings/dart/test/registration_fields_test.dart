// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// An account's RFC 5626 instance id and its own header fields on every
// REGISTER it sends: a push proxy (RFC 8599) refuses one whose `Contact` has
// no `+sip.instance`. A loopback registrar challenges the first REGISTER,
// grants the answer for a few seconds so the refresh comes soon, and writes
// down every REGISTER, the de-registration included.

import 'dart:convert';
import 'dart:io';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

import 'reachability_test.dart' as reach show header;

const _urn = 'urn:uuid:f81d4fae-7ced-11d0-a765-00a0c91e6bf6';

final class Registrar {
  Registrar._(this._socket) {
    _socket.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = _socket.receive();
      if (datagram == null) {
        return;
      }
      final message = utf8.decode(datagram.data, allowMalformed: true);
      if (!message.startsWith('REGISTER ')) {
        return;
      }
      registers.add(message);
      final lines = <String>[];
      for (final name in ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
        final value = reach.header(name, message) ?? '';
        lines.add(
          name == 'To' && !value.contains(';tag=')
              ? 'To: $value;tag=registrar'
              : '$name: $value',
        );
      }
      final String status;
      if (reach.header('Authorization', message) == null &&
          registers.length == 1) {
        status = '401 Unauthorized';
        lines.add(
          'WWW-Authenticate: Digest realm="example.com", nonce="n1", '
          'qop="auth"',
        );
      } else {
        status = '200 OK';
        final expires = reach.header('Expires', message) == '0' ? '0' : '4';
        lines.add(
          'Contact: ${reach.header('Contact', message)};expires=$expires',
        );
      }
      lines.add('Content-Length: 0');
      _socket.send(
        utf8.encode('SIP/2.0 $status\r\n${lines.join('\r\n')}\r\n\r\n'),
        datagram.address,
        datagram.port,
      );
    });
  }

  static Future<Registrar> open() async => Registrar._(
    await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0),
  );

  final RawDatagramSocket _socket;
  final registers = <String>[];

  String get address => '127.0.0.1:${_socket.port}';

  void close() => _socket.close();
}

Future<void> _until(Registrar registrar, int count, Duration within) async {
  final deadline = DateTime.now().add(within);
  while (registrar.registers.length < count &&
      DateTime.now().isBefore(deadline)) {
    await Future<void>.delayed(const Duration(milliseconds: 50));
  }
}

void main() {
  test('the instance and the fields ride on the first REGISTER, the answer '
      'to a challenge, the refresh and the de-registration', () async {
    final registrar = await Registrar.open();
    final stack = await SipralStack.open(bindHost: '127.0.0.1');
    try {
      final account = stack.addAccount(
        'sip:alice@example.com',
        registrarAddress: registrar.address,
        registrar: 'sip:example.com',
        authUser: 'alice',
        authPassword: 'open sesame',
        instanceId: _urn,
        headers: [('X-Push-Key', 'k-17')],
      );
      account.register();
      await _until(registrar, 3, const Duration(seconds: 10));
      expect(registrar.registers.length, greaterThanOrEqualTo(3));
      account.unregister();
      await _until(registrar, 4, const Duration(seconds: 5));
      expect(registrar.registers.length, greaterThanOrEqualTo(4));

      final [first, answered, refresh, goodbye, ...] = registrar.registers;
      expect(reach.header('Authorization', first), isNull);
      expect(reach.header('Authorization', answered), isNotNull);
      expect(reach.header('Expires', goodbye), '0');
      for (final request in [first, answered, refresh, goodbye]) {
        expect(reach.header('X-Push-Key', request), 'k-17');
        expect(
          reach.header('Contact', request),
          contains('+sip.instance="<$_urn>"'),
        );
      }
    } finally {
      await stack.close();
      registrar.close();
    }
  });

  test('a field the stack writes itself is refused', () async {
    final stack = await SipralStack.open(bindHost: '127.0.0.1');
    try {
      expect(
        () => stack.addAccount(
          'sip:alice@example.com',
          registrarAddress: '127.0.0.1:5060',
          registrar: 'sip:example.com',
          headers: [('Expires', '60')],
        ),
        throwsA(
          isA<SipralException>().having(
            (error) => error.status,
            'status',
            SipralStatus.invalidArgument,
          ),
        ),
      );
    } finally {
      await stack.close();
    }
  });
}
