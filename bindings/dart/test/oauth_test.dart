// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Sytek
//
// OAuth 2.0 at the registrar (RFC 8898), through the C ABI: a registrar on a
// loopback port that takes a Bearer token and nothing else asks for one,
// the stack reports where a token comes from, and the token handed to the
// account registers it.

import 'dart:convert';
import 'dart:io';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

import 'reachability_test.dart' as reach show header;

const String authzServer = 'https://as.example.com/oauth2';
const String goodToken = 'access-token-for-alice';

/// A registrar that grants a REGISTER carrying [goodToken] and challenges
/// every other one with `Bearer`, calling any other token `invalid_token`.
final class BearerRegistrar {
  BearerRegistrar._(this._socket) {
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
      final offered = reach.header('Authorization', message);
      authorizations.add(offered);
      final granted = offered == 'Bearer $goodToken';
      final lines = [granted ? 'SIP/2.0 200 OK' : 'SIP/2.0 401 Unauthorized'];
      for (final name in ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
        final value = reach.header(name, message) ?? '';
        lines.add(name == 'To' ? 'To: $value;tag=registrar' : '$name: $value');
      }
      if (granted) {
        lines.add('Contact: ${reach.header('Contact', message)};expires=3600');
      } else {
        final error = offered == null ? '' : ', error="invalid_token"';
        lines.add(
          'WWW-Authenticate: Bearer realm="example.com", scope="sip", '
          'authz_server="$authzServer"$error',
        );
      }
      lines.add('Content-Length: 0');
      _socket.send(
        utf8.encode('${lines.join('\r\n')}\r\n\r\n'),
        datagram.address,
        datagram.port,
      );
    });
  }

  static Future<BearerRegistrar> open() async => BearerRegistrar._(
    await RawDatagramSocket.bind(InternetAddress.loopbackIPv4, 0),
  );

  final RawDatagramSocket _socket;

  /// The `Authorization` of every REGISTER, in order; null for none.
  final List<String?> authorizations = [];

  String get address => '127.0.0.1:${_socket.port}';

  void close() => _socket.close();
}

void main() {
  test(
    'a Bearer challenge asks for a token, and the token registers',
    () async {
      final server = await BearerRegistrar.open();
      final stack = await SipralStack.open(bindHost: '127.0.0.1');
      try {
        final account = stack.addAccount(
          'sip:alice@example.com',
          registrarAddress: server.address,
          registrar: 'sip:example.com',
        );
        final asked = stack.events.firstWhere(
          (event) => event.kind == SipralEventKind.tokenRequired,
        );
        account.register();
        final event = await asked.timeout(const Duration(seconds: 15));
        expect(event.account, account.handle);
        expect(event.tokenAuthzServer, authzServer);
        expect(event.tokenScope, 'sip');
        expect(event.tokenRealm, 'example.com');
        expect(event.tokenServer, server.address);
        expect(event.tokenProxy, isFalse);
        expect(event.tokenError, SipralTokenError.none);

        account.setAccessToken('stale.token');
        final refused = stack.events.firstWhere(
          (event) =>
              event.kind == SipralEventKind.tokenRequired &&
              event.tokenError == SipralTokenError.invalidToken,
        );
        account.register();
        await refused.timeout(const Duration(seconds: 15));

        account.setAccessToken(goodToken);
        await account.registered(timeout: const Duration(seconds: 15));
        expect(server.authorizations.last, 'Bearer $goodToken');
        expect(
          server.authorizations.where(
            (offered) => offered == 'Bearer stale.token',
          ),
          hasLength(1),
          reason: 'a token called invalid is not offered again',
        );

        expect(
          () => account.setAccessToken('two words'),
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
        server.close();
      }
    },
  );
}
