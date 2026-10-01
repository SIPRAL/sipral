// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Sipral-Commercial
// Copyright (c) 2026 Tiberiu Balasea
//
// ABI 0.35 through the Dart layer: an account on a connection of its own
// beside one on the stack's UDP socket, each registered with its own
// loopback registrar and each placing a call through it, and the settings
// read back. The stream registrar is this test's own, over TLS with a
// certificate the `openssl` command makes for the run, or plain TCP.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:sipral/sipral.dart';
import 'package:test/test.dart';

import 'reachability_test.dart' as reach show Registrar, header, until;

const serverName = 'registrar.sipral.test';

/// A registrar on a loopback TCP port, over TLS when given a context,
/// answering every REGISTER 200; every request is kept with the number of
/// the connection it came on, from one.
final class StreamRegistrar {
  StreamRegistrar._(this._listener) {
    _listener.listen((socket) {
      final number = ++_connections;
      _open.add(socket);
      var held = '';
      socket.listen(
        (bytes) {
          held += utf8.decode(bytes, allowMalformed: true);
          while (true) {
            final end = held.indexOf('\r\n\r\n');
            if (end < 0) {
              return;
            }
            final length = int.parse(
              reach.header('Content-Length', held.substring(0, end)) ?? '0',
            );
            if (held.length < end + 4 + length) {
              return;
            }
            final message = held.substring(0, end + 4 + length);
            held = held.substring(end + 4 + length);
            requests.add((number, message));
            if (message.startsWith('REGISTER ')) {
              socket.add(utf8.encode(_ok(message)));
            }
          }
        },
        onError: (Object _) {},
        cancelOnError: true,
      );
    });
  }

  static Future<StreamRegistrar> open([SecurityContext? context]) async =>
      StreamRegistrar._(
        context == null
            ? await ServerSocket.bind(InternetAddress.loopbackIPv4, 0)
            : await SecureServerSocket.bind(
              InternetAddress.loopbackIPv4,
              0,
              context,
            ),
      );

  final Stream<Socket> _listener;
  final List<Socket> _open = [];
  int _connections = 0;
  final List<(int, String)> requests = [];

  int get port => switch (_listener) {
    ServerSocket plain => plain.port,
    SecureServerSocket secure => secure.port,
    _ => 0,
  };
  String get address => '127.0.0.1:$port';
  List<(int, String)> get registers =>
      requests.where((one) => one.$2.startsWith('REGISTER ')).toList();

  /// Close every connection from this end, the way a registrar that
  /// restarted does.
  void drop() {
    for (final socket in _open) {
      socket.destroy();
    }
    _open.clear();
  }

  Future<void> close() async {
    drop();
    switch (_listener) {
      case ServerSocket plain:
        await plain.close();
      case SecureServerSocket secure:
        await secure.close();
    }
  }

  static String _ok(String request) {
    final lines = ['SIP/2.0 200 OK'];
    for (final name in ['Via', 'From', 'To', 'Call-ID', 'CSeq']) {
      final value = reach.header(name, request) ?? '';
      lines.add(name == 'To' ? 'To: $value;tag=registrar' : '$name: $value');
    }
    lines
      ..add('Contact: ${reach.header('Contact', request)};expires=3600')
      ..add('Content-Length: 0');
    return '${lines.join('\r\n')}\r\n\r\n';
  }
}

/// A self-signed certificate for [serverName] and its fingerprint, made with
/// the `openssl` command, or null where there is none.
Future<(SecurityContext, String)?> certificate(Directory directory) async {
  final key = '${directory.path}/registrar.key';
  final pem = '${directory.path}/registrar.pem';
  try {
    final made = await Process.run('openssl', [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', //
      'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
      '-subj', '/CN=$serverName', '-addext', 'subjectAltName=DNS:$serverName',
      '-keyout', key, '-out', pem,
    ]);
    final fingerprint = await Process.run('openssl', [
      'x509', '-in', pem, '-noout', '-fingerprint', '-sha256', //
    ]);
    if (made.exitCode != 0 || fingerprint.exitCode != 0) {
      return null;
    }
    final context =
        SecurityContext()
          ..useCertificateChain(pem)
          ..usePrivateKey(key);
    return (context, (fingerprint.stdout as String).trim());
  } on ProcessException {
    return null;
  }
}

/// An impostor for the registrar [certificate] made in [directory]: a leaf
/// of its own, under a key of its own, sent with the registrar's real
/// certificate above it in the chain, as if that had issued it. Null where
/// there is no `openssl` command.
Future<SecurityContext?> chainAbove(Directory directory) async {
  final path = directory.path;
  final steps = [
    [
      'req', '-x509', '-newkey', 'ec', '-pkeyopt', //
      'ec_paramgen_curve:prime256v1', '-nodes', '-days', '1',
      '-subj', '/CN=$serverName', '-keyout', '$path/issuer.key',
      '-out', '$path/issuer.pem',
    ],
    [
      'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1', //
      '-nodes', '-subj', '/CN=$serverName', '-keyout', '$path/impostor.key',
      '-out', '$path/impostor.csr',
    ],
    [
      'x509', '-req', '-in', '$path/impostor.csr', '-CA', //
      '$path/issuer.pem', '-CAkey', '$path/issuer.key', '-set_serial', '7',
      '-days', '1', '-out', '$path/impostor.pem',
    ],
  ];
  try {
    for (final step in steps) {
      if ((await Process.run('openssl', step)).exitCode != 0) {
        return null;
      }
    }
  } on ProcessException {
    return null;
  }
  final chain = File('$path/chain.pem');
  await chain.writeAsString(
    await File('$path/impostor.pem').readAsString() +
        await File('$path/registrar.pem').readAsString(),
  );
  return SecurityContext()
    ..useCertificateChain(chain.path)
    ..usePrivateKey('$path/impostor.key');
}

void main() {
  final opened = <SipralStack>[];

  tearDown(() async {
    for (final stack in opened) {
      await stack.close();
    }
    opened.clear();
  });

  Future<SipralStack> stack() async {
    final made = await SipralStack.open(bindHost: '127.0.0.1');
    opened.add(made);
    return made;
  }

  test(
    'an account over TLS and one over UDP each reach their own server',
    () async {
      final directory = await Directory.systemTemp.createTemp('sipral-dart');
      addTearDown(() => directory.delete(recursive: true));
      final made = await certificate(directory);
      if (made == null) {
        markTestSkipped('no openssl command to make the certificate with');
        return;
      }
      final udp = await reach.Registrar.open();
      addTearDown(udp.close);
      final tls = await StreamRegistrar.open(made.$1);
      addTearDown(tls.close);
      final client = await stack();
      final wanted = <SipralStackEvent>[];
      final watching = client.events.listen((event) {
        if (event.kind == SipralEventKind.transportWanted) {
          wanted.add(event);
        }
      });
      addTearDown(watching.cancel);

      final overUdp = client.addAccount(
        'sip:alice@udp.sipral.test',
        registrarAddress: udp.address,
        registrar: 'sip:udp.sipral.test',
      );
      // the fingerprint as `openssl x509 -fingerprint -sha256` printed it
      final overTls = client.addAccount(
        'sip:bob@$serverName',
        registrarAddress: tls.address,
        registrar: 'sip:$serverName',
        tlsPin: made.$2,
        streamProtocol: SipralTransport.tls,
      );
      expect(overTls.streamProtocol, SipralTransport.tls);
      expect(overUdp.streamProtocol, isNull);
      await overUdp.registered();
      await overTls.registered();

      expect(wanted, hasLength(1));
      final register = tls.registers.single;
      expect(reach.header('Via', register.$2), startsWith('SIP/2.0/TLS '));
      expect(reach.header('Contact', register.$2), contains(';transport=tls'));
      expect(register.$2, contains('sip:bob@'));
      expect(udp.registers, isNotEmpty);
      expect(udp.registers.every((one) => one.contains('sip:alice@')), isTrue);

      final first = await client.placeCall(
        overUdp,
        'sip:carol@udp.sipral.test',
      );
      final second = await client.placeCall(overTls, 'sip:dave@$serverName');
      addTearDown(first.close);
      addTearDown(second.close);
      await reach.until(
        () => udp.received.any((one) => one.startsWith('INVITE sip:carol@')),
      );
      await reach.until(
        () => tls.requests.any((one) => one.$2.startsWith('INVITE sip:dave@')),
      );
      final invite = tls.requests.firstWhere(
        (one) => one.$2.startsWith('INVITE '),
      );
      expect(invite.$1, register.$1, reason: 'over the account\'s own one');
      expect(reach.header('Via', invite.$2), startsWith('SIP/2.0/TLS '));
      expect(udp.received.any((one) => one.contains('dave@')), isFalse);
      expect(tls.requests.any((one) => one.$2.contains('carol@')), isFalse);
    },
  );

  test(
    'a server that sends the pinned certificate above a leaf of its own is refused',
    () async {
      final directory = await Directory.systemTemp.createTemp('sipral-dart');
      addTearDown(() => directory.delete(recursive: true));
      final made = await certificate(directory);
      final impostor = made == null ? null : await chainAbove(directory);
      if (made == null || impostor == null) {
        markTestSkipped('no openssl command to make the certificates with');
        return;
      }
      final tls = await StreamRegistrar.open(impostor);
      addTearDown(tls.close);
      final client = await stack();
      final account = client.addAccount(
        'sip:bob@$serverName',
        registrarAddress: tls.address,
        registrar: 'sip:$serverName',
        tlsPin: made.$2,
        streamProtocol: SipralTransport.tls,
      );
      final settled = account.registration
          .firstWhere(
            (state) =>
                state == SipralRegistrationState.registered ||
                state == SipralRegistrationState.retrying ||
                state == SipralRegistrationState.failed,
          )
          .timeout(const Duration(seconds: 30));
      account.register();
      // the pinned certificate is in the chain, but the leaf, whose key
      // signed the handshake, is the impostor's own: no connection is
      // bound, and the registration gives up waiting for one
      expect(await settled, isNot(SipralRegistrationState.registered));
      expect(tls.requests, isEmpty, reason: 'nothing went to the impostor');
    },
    timeout: const Timeout(Duration(seconds: 60)),
  );

  test(
    'an account over TCP is opened again when its server drops it',
    () async {
      final registrar = await StreamRegistrar.open();
      addTearDown(registrar.close);
      final client = await stack();
      final account = client.addAccount(
        'sip:alice@$serverName',
        registrarAddress: registrar.address,
        registrar: 'sip:$serverName',
        streamProtocol: SipralTransport.tcp,
      );
      await account.registered();
      final register = registrar.registers.single;
      expect(reach.header('Via', register.$2), startsWith('SIP/2.0/TCP '));
      expect(reach.header('Contact', register.$2), contains(';transport=tcp'));

      registrar.drop();
      await reach.until(
        () => registrar.registers.any((one) => one.$1 == 2),
        within: const Duration(seconds: 10),
      );
      expect(
        () => client.addAccount(
          'sip:carol@example.com',
          registrarAddress: '127.0.0.1:5060',
          streamProtocol: SipralTransport.udp,
        ),
        throwsArgumentError,
      );
    },
  );

  test('the settings are read back with the defaults filled in', () async {
    final plain = await stack();
    final defaults = plain.settings();
    expect(defaults.transport, SipralTransport.udp);
    expect(defaults.retransmits, isTrue);
    expect(defaults.systemEchoCancellation, isTrue);
    expect(defaults.pseudonymSalted, isFalse);
    expect(defaults.diagnosticTrace, isFalse);
    expect(defaults.srtpSuites, isNotEmpty);
    expect(defaults.codecCount, greaterThan(0));
    expect(defaults.rtpPorts, isNull);

    final given = await SipralStack.open(
      bindHost: '127.0.0.1',
      srtpSuites: ['AES_CM_128_HMAC_SHA1_32', 'AES_CM_128_HMAC_SHA1_80'],
      pseudonymSalt: List.filled(16, 7),
      diagnosticTrace: true,
    );
    opened.add(given);
    final settings = given.settings();
    expect(settings.srtpSuites, [
      SipralSrtpSuite.aesCm32,
      SipralSrtpSuite.aesCm80,
    ]);
    expect(settings.pseudonymSalted, isTrue);
    expect(settings.diagnosticTrace, isTrue);
    given.setDiagnosticTrace(false);
    expect(given.settings().diagnosticTrace, isFalse);
  });
}
