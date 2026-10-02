// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// Whose challenge an account's password answers, and what a held party is
// sent: the realms an account names reach the library, a challenge under
// any other is declined and reported with who asked and for what, and the
// stack's held audio is the library's to check.

import 'dart:convert';
import 'dart:io';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

import 'reachability_test.dart' as reach show header;

/// A server that refuses every INVITE with a 407 under [realm].
final class Challenger {
  Challenger._(this._socket, this.realm) {
    _socket.listen((event) {
      if (event != RawSocketEvent.read) {
        return;
      }
      final datagram = _socket.receive();
      if (datagram == null) {
        return;
      }
      final message = utf8.decode(datagram.data, allowMalformed: true);
      if (!message.startsWith('INVITE ')) {
        return;
      }
      final lines = ['SIP/2.0 407 Proxy Authentication Required'];
      for (final name in ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
        final value = reach.header(name, message) ?? '';
        lines.add(name == 'To' ? 'To: $value;tag=sbc' : '$name: $value');
      }
      lines
        ..add(
          'Proxy-Authenticate: Digest realm="$realm", nonce="n-$realm", '
          'qop="auth"',
        )
        ..add('Content-Length: 0');
      _socket.send(
        utf8.encode('${lines.join('\r\n')}\r\n\r\n'),
        datagram.address,
        datagram.port,
      );
    });
  }

  static Future<Challenger> open(String realm) async => Challenger._(
    await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0),
    realm,
  );

  final RawDatagramSocket _socket;
  final String realm;

  String get address => '127.0.0.1:${_socket.port}';

  void close() => _socket.close();
}

void main() {
  test('a challenge under a realm the account does not name is declined '
      'and reported with who asked and for what', () async {
    final server = await Challenger.open('callee.example');
    final stack = await SipralStack.open(bindHost: '127.0.0.1');
    try {
      final account = stack.addAccount(
        'sip:alice@sipral.invalid',
        registrarAddress: server.address,
        authUser: 'alice',
        authPassword: 'open sesame',
        realms: ['registrar.example', 'sbc, inc.'],
      );
      final declined = stack.events.firstWhere(
        (event) => event.kind == SipralEventKind.challengeDeclined,
      );
      final call = await stack.placeCall(account, 'sip:bob@${server.address}');
      final event = await declined.timeout(const Duration(seconds: 15));
      expect(event.account, account.handle);
      expect(
        event.challengeRefusal,
        SipralChallengeRefusal.notTheAccountsRealm,
      );
      expect(event.challengeServer, server.address);
      expect(event.challengeRealms, ['callee.example']);
      call.close();
    } finally {
      await stack.close();
      server.close();
    }
  });

  test(
    'a realm with a control byte in it is the library\'s to refuse',
    () async {
      final stack = await SipralStack.open(bindHost: '127.0.0.1');
      try {
        expect(
          () => stack.addAccount(
            'sip:alice@sipral.invalid',
            registrarAddress: '127.0.0.1:5060',
            realms: ['registrar.example', 'sbc\texample'],
          ),
          throwsA(
            isA<SipralException>().having(
              (e) => e.status,
              'status',
              SipralStatus.invalidArgument,
            ),
          ),
        );
      } finally {
        await stack.close();
      }
    },
  );

  test('what a held party is sent reaches the library, which refuses a '
      'value it has no name for', () async {
    final silent = await SipralStack.open(
      bindHost: '127.0.0.1',
      heldAudio: SipralHeldAudio.silence,
    );
    await silent.close();
    await expectLater(
      SipralStack.open(bindHost: '127.0.0.1', heldAudio: 3),
      throwsA(
        isA<SipralException>().having(
          (e) => e.status,
          'status',
          SipralStatus.invalidArgument,
        ),
      ),
    );
  });
}
