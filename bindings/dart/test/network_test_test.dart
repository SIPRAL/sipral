// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// The network test before a call, through the C ABI: a server on a loopback
// port answers the test's OPTIONS, and the stack reports it reached, timed,
// with a verdict.

import 'dart:convert';
import 'dart:io';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

import 'reachability_test.dart' as reach show header;

void main() {
  test('the account\'s server answers the test\'s OPTIONS', () async {
    final server = await RawDatagramSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
    );
    final asked = <String>[];
    server.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = server.receive();
      if (datagram == null) {
        return;
      }
      final message = utf8.decode(datagram.data, allowMalformed: true);
      asked.add(message.split('\r\n').first);
      if (!message.startsWith('OPTIONS ')) {
        return;
      }
      final lines = ['SIP/2.0 200 OK'];
      for (final name in ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
        final value = reach.header(name, message) ?? '';
        lines.add(name == 'To' ? 'To: $value;tag=server' : '$name: $value');
      }
      lines.add('Content-Length: 0');
      server.send(
        utf8.encode('${lines.join('\r\n')}\r\n\r\n'),
        datagram.address,
        datagram.port,
      );
    });
    final stack = await SipralStack.open(bindHost: '127.0.0.1');
    try {
      final account = stack.addAccount(
        'sip:alice@example.com',
        registrarAddress: '127.0.0.1:${server.port}',
        registrar: 'sip:example.com',
      );
      final tested = stack.events.firstWhere(
        (event) => event.kind == SipralEventKind.networkTest,
      );
      final number = stack.networkTest(account: account);
      final event = await tested.timeout(const Duration(seconds: 15));
      final found = event.networkTest!;
      expect(found.test, number);
      expect(event.account, account.handle);
      expect(found.server, SipralServerReach.answered);
      expect(found.serverStatus, 200);
      expect(found.stun, SipralNetworkProbe.notTested);
      expect(found.echo, SipralNetworkProbe.notTested);
      expect(found.verdict, SipralNetworkVerdict.good);
      expect(asked, everyElement(startsWith('OPTIONS ')));
    } finally {
      await stack.close();
      server.close();
    }
  });
}
